// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "agent_events.h"

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define SOCK_STREAM 1

enum network_stat_index {
	NETWORK_STAT_MAP_UPDATE_FAILED = 0,
	NETWORK_STAT_SOCKET_READ_FAILED = 1,
	NETWORK_STAT_RINGBUF_LOST = 2,
	NETWORK_STAT_USER_READ_FAILED = 3,
	NETWORK_STAT_FILTERED = 4,
	NETWORK_STAT_RATE_LIMITED = 5,
	NETWORK_STAT_MAX = 6,
};

enum socket_metadata_result {
	SOCKET_METADATA_VALID = 1U << 0,
	SOCKET_LOCAL_VALID = 1U << 1,
	SOCKET_PEER_VALID = 1U << 2,
};

struct pending_network_call {
	struct agent_event_header header;
	struct agent_network_payload network;
	__u64 rate_interval_ns;
	__u64 rate_burst_ns;
	__u16 port_filter;
	__u8 protocol_filter;
	__u8 reserved[5];
};

struct network_filter {
	__u64 rate_interval_ns;
	__u64 rate_burst_ns;
	__u16 destination_port;
	__u8 protocol;
	__u8 reserved;
};

struct observed_socket {
	__u64 socket_cookie;
	__u64 network_namespace_cookie;
	__u64 cgroup_id;
};

struct network_rate_key {
	__u64 cgroup_id;
	__u32 tgid;
	__u16 port;
	__u16 event_type;
	__u8 protocol;
	__u8 reserved[7];
};

struct network_rate_value {
	__u64 next_event_ns;
};

/* One thread cannot execute two network syscalls concurrently. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct pending_network_call);
} active_network_calls SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct observed_socket);
} observed_sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024);
} network_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, NETWORK_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} network_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct agent_config);
} network_config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct network_rate_key);
	__type(value, struct network_rate_value);
} network_rate_limits SEC(".maps");

static __always_inline void increment_stat(__u32 index)
{
	__u64 *value;

	if (index >= NETWORK_STAT_MAX)
		return;
	value = bpf_map_lookup_elem(&network_stats, &index);
	if (value)
		(*value)++;
}

/* Lock-free GCRA token bucket. The retry bound keeps verifier complexity O(1). */
static __always_inline int rate_limit_allows(
	__u64 cgroup_id, __u32 tgid, __u16 event_type, __u8 protocol,
	__u16 port, __u64 interval, __u64 burst_ns)
{
	struct network_rate_key key = {
		.cgroup_id = cgroup_id,
		.tgid = tgid,
		.port = port,
		.event_type = event_type,
		.protocol = protocol,
	};
	struct network_rate_value initial = {};
	struct network_rate_value *state;
	__u64 now;
	int attempt;

	if (!interval)
		return 1;
	now = bpf_ktime_get_ns();
	state = bpf_map_lookup_elem(&network_rate_limits, &key);
	if (!state) {
		initial.next_event_ns = now + interval;
		if (!bpf_map_update_elem(&network_rate_limits, &key, &initial,
					 BPF_NOEXIST))
			return 1;
		state = bpf_map_lookup_elem(&network_rate_limits, &key);
		if (!state)
			return 0;
	}

#pragma unroll
	for (attempt = 0; attempt < 4; attempt++) {
		__u64 current = state->next_event_ns;
		__u64 base;
		__u64 desired;
		__u64 previous;

		if (current > now + burst_ns)
			return 0;
		base = current > now ? current : now;
		desired = base + interval;
		previous = __sync_val_compare_and_swap(&state->next_event_ns,
						       current, desired);
		if (previous == current)
			return 1;
	}
	return 0;
}

/*
 * If a task belongs to another PID namespace, namespace translation fails.
 * Such tasks must remain visible when no explicit target PID was requested.
 */
static __always_inline int network_event_enabled(
	__u16 event_type, __u32 *namespace_pid, __u32 *namespace_tgid,
	struct network_filter *filter, __u64 *current_cgroup_id)
{
	struct bpf_pidns_info namespace_ids = {};
	const struct agent_config *config;
	__u64 pid_tgid;
	__u64 cgroup_id;
	__u32 key = 0;
	int namespace_matches = 1;

	config = bpf_map_lookup_elem(&network_config_map, &key);
	if (!config || !(config->event_mask & AGENT_EVENT_BIT(event_type)))
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	*namespace_pid = (__u32)pid_tgid;
	*namespace_tgid = pid_tgid >> 32;
	if (config->pidns_inode) {
		namespace_matches = 0;
		if (!bpf_get_ns_current_pid_tgid(config->pidns_device,
						 config->pidns_inode,
						 &namespace_ids,
						 sizeof(namespace_ids))) {
			namespace_matches = 1;
			*namespace_pid = namespace_ids.pid;
			*namespace_tgid = namespace_ids.tgid;
		}
	}

	if (config->exclude_tgid && namespace_matches &&
	    config->exclude_tgid == *namespace_tgid)
		return 0;
	if (config->target_tgid &&
	    (!namespace_matches || config->target_tgid != *namespace_tgid))
		return 0;

	cgroup_id = bpf_get_current_cgroup_id();
	if (config->target_cgroup_id &&
	    config->target_cgroup_id != cgroup_id)
		return 0;

	filter->destination_port = config->network_destination_port;
	filter->protocol = config->network_protocol;
	filter->rate_interval_ns = config->network_rate_interval_ns;
	filter->rate_burst_ns = config->network_rate_burst_ns;
	*current_cgroup_id = cgroup_id;
	return 1;
}

static __always_inline void fill_common_header(
	struct agent_event_header *header, __u16 event_type,
	__u32 namespace_pid, __u32 namespace_tgid, __u64 cgroup_id)
{
	struct task_struct *task;
	__u64 pid_tgid;
	__u64 uid_gid;

	pid_tgid = bpf_get_current_pid_tgid();
	uid_gid = bpf_get_current_uid_gid();
	task = (struct task_struct *)bpf_get_current_task_btf();

	header->timestamp_ns = bpf_ktime_get_ns();
	header->cgroup_id = cgroup_id;
	header->pid = (__u32)pid_tgid;
	header->tgid = pid_tgid >> 32;
	header->namespace_pid = namespace_pid;
	header->namespace_tgid = namespace_tgid;
	header->uid = (__u32)uid_gid;
	header->gid = uid_gid >> 32;
	header->cpu = bpf_get_smp_processor_id();
	header->size = AGENT_NETWORK_EVENT_SIZE;
	header->version = AGENT_SCHEMA_VERSION;
	header->type = event_type;

	if (task) {
		header->ppid = BPF_CORE_READ(task, real_parent, tgid);
		if (bpf_core_field_exists(task->start_boottime))
			header->task_start_ns = BPF_CORE_READ(task, start_boottime);
		else if (bpf_core_field_exists(task->start_time))
			header->task_start_ns = BPF_CORE_READ(task, start_time);
	}
	bpf_get_current_comm(header->comm, sizeof(header->comm));
}

/* SockOps on kernels before 6.10 cannot use current-task/cgroup helpers. */
static __always_inline void fill_sockops_header(
	struct agent_event_header *header, __u64 cgroup_id)
{
	header->timestamp_ns = bpf_ktime_get_ns();
	header->cgroup_id = cgroup_id;
	header->size = AGENT_NETWORK_EVENT_SIZE;
	header->version = AGENT_SCHEMA_VERSION;
	header->type = AGENT_EVENT_NETWORK_TCP_STATE;
}

static __always_inline int address_present(__u16 family,
					    const __u8 address[16])
{
	int index;
	int length = family == AF_INET ? 4 : 16;

#pragma unroll
	for (index = 0; index < 16; index++) {
		if (index < length && address[index])
			return 1;
	}
	return 0;
}

static __always_inline int parse_user_address(
	const struct sockaddr *user_address, __u32 address_length,
	struct agent_network_payload *network, int destination)
{
	__u16 family;

	if (!user_address)
		return 0;
	if (bpf_probe_read_user(&family, sizeof(family),
				&user_address->sa_family))
		return -1;
	if (family != AF_INET && family != AF_INET6)
		return 0;
	if (network->address_family && network->address_family != family)
		return 0;
	network->address_family = family;

	if (family == AF_INET) {
		struct sockaddr_in address = {};
		__u16 port;

		if (address_length < sizeof(address) ||
		    bpf_probe_read_user(&address, sizeof(address), user_address))
			return -1;
		port = bpf_ntohs(address.sin_port);
		if (destination) {
			network->destination_port = port;
			__builtin_memcpy(network->destination_address,
					 &address.sin_addr.s_addr, 4);
		} else {
			network->source_port = port;
			__builtin_memcpy(network->source_address,
					 &address.sin_addr.s_addr, 4);
		}
	} else {
		struct sockaddr_in6 address = {};
		__u16 port;

		if (address_length < sizeof(address) ||
		    bpf_probe_read_user(&address, sizeof(address), user_address))
			return -1;
		port = bpf_ntohs(address.sin6_port);
		if (destination) {
			network->destination_port = port;
			network->destination_scope_id = address.sin6_scope_id;
			__builtin_memcpy(network->destination_address,
					 address.sin6_addr.in6_u.u6_addr8, 16);
		} else {
			network->source_port = port;
			network->source_scope_id = address.sin6_scope_id;
			__builtin_memcpy(network->source_address,
					 address.sin6_addr.in6_u.u6_addr8, 16);
		}
	}
	return 1;
}

/* Returns a bitmask of socket, local-endpoint and peer-endpoint validity. */
static __always_inline int read_socket_metadata(
	int socket_fd, struct agent_network_payload *network,
	int read_local, int read_peer)
{
	struct task_struct *task;
	struct files_struct *files;
	struct fdtable *fdtable;
	struct file **fd_array;
	struct file *file = 0;
	struct socket *socket;
	struct sock *sk;
	struct net *net;
	__u32 max_fds;
	__u16 family;
	int result = 0;

	if (socket_fd < 0)
		return 0;
	task = (struct task_struct *)bpf_get_current_task_btf();
	if (!task)
		return 0;
	files = BPF_CORE_READ(task, files);
	if (!files)
		return 0;
	fdtable = BPF_CORE_READ(files, fdt);
	if (!fdtable)
		return 0;
	max_fds = BPF_CORE_READ(fdtable, max_fds);
	if ((__u32)socket_fd >= max_fds)
		return 0;
	fd_array = BPF_CORE_READ(fdtable, fd);
	if (!fd_array || bpf_core_read(&file, sizeof(file),
				       &fd_array[socket_fd]))
		return 0;

	socket = BPF_CORE_READ(file, private_data);
	if (!socket)
		return 0;
	sk = BPF_CORE_READ(socket, sk);
	if (!sk)
		return 0;
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;
	if (network->address_family && network->address_family != family)
		return 0;

	network->address_family = family;
	network->socket_type = BPF_CORE_READ(socket, type);
	network->protocol = BPF_CORE_READ(sk, sk_protocol);
	if (bpf_core_field_exists(sk->__sk_common.skc_cookie.counter)) {
		__s64 socket_cookie =
			BPF_CORE_READ(sk, __sk_common.skc_cookie.counter);

		if (socket_cookie > 0)
			network->socket_cookie = socket_cookie;
	}
	net = BPF_CORE_READ(sk, __sk_common.skc_net.net);
	if (net)
		network->network_namespace_id = BPF_CORE_READ(net, ns.inum);
	result |= SOCKET_METADATA_VALID;

	if (read_local) {
		network->source_port = BPF_CORE_READ(sk, __sk_common.skc_num);
		if (family == AF_INET) {
			__u32 address =
				BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
			__builtin_memcpy(network->source_address, &address, 4);
		} else {
			BPF_CORE_READ_INTO(
				&network->source_address, sk,
				__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		}
		if (address_present(family, network->source_address))
			result |= SOCKET_LOCAL_VALID;
	}

	if (read_peer) {
		__u16 destination_port =
			BPF_CORE_READ(sk, __sk_common.skc_dport);
		network->destination_port = bpf_ntohs(destination_port);
		if (family == AF_INET) {
			__u32 address = BPF_CORE_READ(sk, __sk_common.skc_daddr);
			__builtin_memcpy(network->destination_address, &address, 4);
		} else {
			BPF_CORE_READ_INTO(
				&network->destination_address, sk,
				__sk_common.skc_v6_daddr.in6_u.u6_addr8);
		}
		if (address_present(family, network->destination_address))
			result |= SOCKET_PEER_VALID;
	}
	return result;
}

static __always_inline void swap_endpoints(struct agent_network_payload *network)
{
	__u16 port = network->source_port;
	__u32 scope = network->source_scope_id;
	int index;

	network->source_port = network->destination_port;
	network->destination_port = port;
	network->source_scope_id = network->destination_scope_id;
	network->destination_scope_id = scope;
#pragma unroll
	for (index = 0; index < 16; index++) {
		__u8 byte = network->source_address[index];
		network->source_address[index] = network->destination_address[index];
		network->destination_address[index] = byte;
	}
}

static __always_inline struct pending_network_call *begin_call(
	__u16 event_type, int socket_fd)
{
	struct pending_network_call *pending;
	struct network_filter filter = {};
	struct task_struct *task;
	__u64 cgroup_id;
	__u32 namespace_pid;
	__u32 namespace_tgid;

	if (!network_event_enabled(event_type, &namespace_pid, &namespace_tgid,
				   &filter, &cgroup_id))
		return 0;
	task = (struct task_struct *)bpf_get_current_task_btf();
	pending = bpf_task_storage_get(&active_network_calls, task, 0,
				       BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!pending) {
		increment_stat(NETWORK_STAT_MAP_UPDATE_FAILED);
		return 0;
	}
	__builtin_memset(pending, 0, sizeof(*pending));
	fill_common_header(&pending->header, event_type,
			   namespace_pid, namespace_tgid, cgroup_id);
	pending->network.socket_fd = socket_fd;
	pending->rate_interval_ns = filter.rate_interval_ns;
	pending->rate_burst_ns = filter.rate_burst_ns;
	pending->port_filter = filter.destination_port;
	pending->protocol_filter = filter.protocol;
	return pending;
}

static __always_inline int port_matches(const struct pending_network_call *pending)
{
	__u16 event_type = pending->header.type;
	__u16 port;

	if (!pending->port_filter)
		return 1;
	if (event_type == AGENT_EVENT_NETWORK_BIND ||
	    event_type == AGENT_EVENT_NETWORK_LISTEN)
		port = pending->network.source_port;
	else
		port = pending->network.destination_port;
	return port == pending->port_filter;
}

static __always_inline int store_pending(struct pending_network_call *pending)
{
	struct task_struct *task;

	if (pending->port_filter && pending->network.destination_port &&
	    !port_matches(pending)) {
		increment_stat(NETWORK_STAT_FILTERED);
		task = (struct task_struct *)bpf_get_current_task_btf();
		if (task)
			bpf_task_storage_delete(&active_network_calls, task);
		return 0;
	}
	return 1;
}

static __always_inline void delete_pending(struct task_struct *task)
{
	if (task)
		bpf_task_storage_delete(&active_network_calls, task);
}

static __always_inline void delete_current_pending(void)
{
	struct task_struct *task =
		(struct task_struct *)bpf_get_current_task_btf();

	delete_pending(task);
}

static __always_inline void apply_metadata_flags(
	struct agent_event_header *header, int metadata)
{
	if (metadata & SOCKET_METADATA_VALID)
		header->flags |= AGENT_FLAG_NETWORK_SOCKET_VALID;
	if (metadata & SOCKET_LOCAL_VALID)
		header->flags |= AGENT_FLAG_NETWORK_SOURCE_VALID;
	if (metadata & SOCKET_PEER_VALID)
		header->flags |= AGENT_FLAG_NETWORK_DEST_VALID;
}

static __always_inline int complete_call(__u16 expected_type,
					  __s64 return_value)
{
	struct pending_network_call *pending;
	struct agent_network_payload *network;
	struct agent_event *output;
	struct task_struct *task;
	__u64 completed_at;
	__u16 rate_port;
	int metadata = 0;
	int metadata_expected = 1;

	task = (struct task_struct *)bpf_get_current_task_btf();
	pending = bpf_task_storage_get(&active_network_calls, task, 0, 0);
	if (!pending)
		return 0;
	if (pending->header.type != expected_type) {
		delete_pending(task);
		return 0;
	}

	network = &pending->network;
	completed_at = bpf_ktime_get_ns();
	pending->header.result = (__s32)return_value;
	network->return_value = return_value;
	network->duration_ns = completed_at - pending->header.timestamp_ns;

	if (expected_type == AGENT_EVENT_NETWORK_ACCEPT) {
		if (return_value < 0) {
			delete_pending(task);
			return 0;
		}
		network->socket_fd = (__u32)return_value;
		metadata = read_socket_metadata(network->socket_fd, network, 1, 1);
		swap_endpoints(network);
		/* After swapping: source=remote peer, destination=local. */
		if (metadata & SOCKET_LOCAL_VALID)
			pending->header.flags |= AGENT_FLAG_NETWORK_DEST_VALID;
		if (metadata & SOCKET_PEER_VALID)
			pending->header.flags |= AGENT_FLAG_NETWORK_SOURCE_VALID;
		if (metadata & SOCKET_METADATA_VALID)
			pending->header.flags |= AGENT_FLAG_NETWORK_SOCKET_VALID;
	} else if (expected_type == AGENT_EVENT_NETWORK_UDP_SEND) {
		metadata = read_socket_metadata(network->socket_fd, network, 1,
						!((pending->header.flags &
						   AGENT_FLAG_NETWORK_DEST_VALID)));
		apply_metadata_flags(&pending->header, metadata);
	} else {
		metadata = read_socket_metadata(network->socket_fd, network, 1, 0);
		apply_metadata_flags(&pending->header, metadata);
	}
	if ((expected_type == AGENT_EVENT_NETWORK_ACCEPT ||
	     expected_type == AGENT_EVENT_NETWORK_LISTEN) &&
	    !(metadata & SOCKET_METADATA_VALID)) {
		delete_pending(task);
		return 0;
	}
	if (network->socket_cookie)
		pending->header.flags |= AGENT_FLAG_NETWORK_COOKIE_VALID;
	if (network->network_namespace_cookie)
		pending->header.flags |= AGENT_FLAG_NETWORK_NETNS_COOKIE_VALID;

	if (expected_type == AGENT_EVENT_NETWORK_UDP_SEND &&
	    !network->address_family && !(metadata & SOCKET_METADATA_VALID))
		metadata_expected = 0;
	if (metadata_expected && !(metadata & SOCKET_METADATA_VALID) &&
	    !(pending->header.flags & AGENT_FLAG_NETWORK_SOCKET_VALID))
		increment_stat(NETWORK_STAT_SOCKET_READ_FAILED);
	if (pending->protocol_filter &&
	    network->protocol != pending->protocol_filter) {
		increment_stat(NETWORK_STAT_FILTERED);
		delete_pending(task);
		return 0;
	}
	if (!port_matches(pending)) {
		increment_stat(NETWORK_STAT_FILTERED);
		delete_pending(task);
		return 0;
	}
	if (expected_type == AGENT_EVENT_NETWORK_UDP_SEND &&
	    network->protocol != IPPROTO_UDP) {
		delete_pending(task);
		return 0;
	}
	rate_port = (expected_type == AGENT_EVENT_NETWORK_BIND ||
		     expected_type == AGENT_EVENT_NETWORK_LISTEN)
			    ? network->source_port
			    : network->destination_port;
	if (!rate_limit_allows(pending->header.cgroup_id,
			       pending->header.tgid, pending->header.type,
			       network->protocol, rate_port,
			       pending->rate_interval_ns,
			       pending->rate_burst_ns)) {
		increment_stat(NETWORK_STAT_RATE_LIMITED);
		delete_pending(task);
		return 0;
	}
	output = bpf_ringbuf_reserve(&network_events,
				     AGENT_NETWORK_EVENT_SIZE, 0);
	if (!output) {
		increment_stat(NETWORK_STAT_RINGBUF_LOST);
		delete_pending(task);
		return 0;
	}
	__builtin_memset(output, 0, AGENT_NETWORK_EVENT_SIZE);
	__builtin_memcpy(&output->header, &pending->header,
			 sizeof(output->header));
	__builtin_memcpy(&output->data.network, network, sizeof(*network));
	bpf_ringbuf_submit(output, 0);
	delete_pending(task);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_enter(struct trace_event_raw_sys_enter *ctx)
{
	struct pending_network_call *pending;
	const struct sockaddr *address = (const struct sockaddr *)ctx->args[1];
	int parsed;

	pending = begin_call(AGENT_EVENT_NETWORK_CONNECT, (int)ctx->args[0]);
	if (!pending)
		return 0;
	parsed = parse_user_address(address, (__u32)ctx->args[2],
				    &pending->network, 1);
	if (parsed <= 0) {
		if (parsed < 0)
			increment_stat(NETWORK_STAT_USER_READ_FAILED);
		delete_current_pending();
		return 0;
	}
	pending->header.flags |= AGENT_FLAG_NETWORK_DEST_VALID;
	store_pending(pending);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int trace_connect_exit(struct trace_event_raw_sys_exit *ctx)
{
	return complete_call(AGENT_EVENT_NETWORK_CONNECT, (__s64)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_bind")
int trace_bind_enter(struct trace_event_raw_sys_enter *ctx)
{
	struct pending_network_call *pending;
	const struct sockaddr *address = (const struct sockaddr *)ctx->args[1];
	int parsed;

	pending = begin_call(AGENT_EVENT_NETWORK_BIND, (int)ctx->args[0]);
	if (!pending)
		return 0;
	parsed = parse_user_address(address, (__u32)ctx->args[2],
				    &pending->network, 0);
	if (parsed <= 0) {
		if (parsed < 0)
			increment_stat(NETWORK_STAT_USER_READ_FAILED);
		delete_current_pending();
		return 0;
	}
	pending->header.flags |= AGENT_FLAG_NETWORK_SOURCE_VALID;
	store_pending(pending);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_bind")
int trace_bind_exit(struct trace_event_raw_sys_exit *ctx)
{
	return complete_call(AGENT_EVENT_NETWORK_BIND, (__s64)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_listen")
int trace_listen_enter(struct trace_event_raw_sys_enter *ctx)
{
	struct pending_network_call *pending;

	pending = begin_call(AGENT_EVENT_NETWORK_LISTEN, (int)ctx->args[0]);
	if (!pending)
		return 0;
	pending->network.backlog = (__s32)ctx->args[1];
	store_pending(pending);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_listen")
int trace_listen_exit(struct trace_event_raw_sys_exit *ctx)
{
	return complete_call(AGENT_EVENT_NETWORK_LISTEN, (__s64)ctx->ret);
}

static __always_inline int begin_accept(struct trace_event_raw_sys_enter *ctx)
{
	struct pending_network_call *pending;

	pending = begin_call(AGENT_EVENT_NETWORK_ACCEPT, (int)ctx->args[0]);
	if (!pending)
		return 0;
	store_pending(pending);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int trace_accept_enter(struct trace_event_raw_sys_enter *ctx)
{
	return begin_accept(ctx);
}

SEC("tracepoint/syscalls/sys_exit_accept")
int trace_accept_exit(struct trace_event_raw_sys_exit *ctx)
{
	return complete_call(AGENT_EVENT_NETWORK_ACCEPT, (__s64)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_accept4_enter(struct trace_event_raw_sys_enter *ctx)
{
	return begin_accept(ctx);
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int trace_accept4_exit(struct trace_event_raw_sys_exit *ctx)
{
	return complete_call(AGENT_EVENT_NETWORK_ACCEPT, (__s64)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto_enter(struct trace_event_raw_sys_enter *ctx)
{
	struct pending_network_call *pending;
	const struct sockaddr *address = (const struct sockaddr *)ctx->args[4];
	int parsed;

	pending = begin_call(AGENT_EVENT_NETWORK_UDP_SEND, (int)ctx->args[0]);
	if (!pending)
		return 0;
	pending->network.bytes_requested = ctx->args[2];
	if (address) {
		parsed = parse_user_address(address, (__u32)ctx->args[5],
					    &pending->network, 1);
		if (parsed <= 0) {
			if (parsed < 0)
				increment_stat(NETWORK_STAT_USER_READ_FAILED);
			delete_current_pending();
			return 0;
		}
		pending->header.flags |= AGENT_FLAG_NETWORK_DEST_VALID;
	}
	store_pending(pending);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int trace_sendto_exit(struct trace_event_raw_sys_exit *ctx)
{
	return complete_call(AGENT_EVENT_NETWORK_UDP_SEND, (__s64)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_sendmsg_enter(struct trace_event_raw_sys_enter *ctx)
{
	const struct user_msghdr *user_message =
		(const struct user_msghdr *)ctx->args[1];
	struct pending_network_call *pending;
	struct user_msghdr message = {};
	int parsed;

	pending = begin_call(AGENT_EVENT_NETWORK_UDP_SEND, (int)ctx->args[0]);
	if (!pending)
		return 0;
	if (!user_message ||
	    bpf_probe_read_user(&message, sizeof(message), user_message)) {
		increment_stat(NETWORK_STAT_USER_READ_FAILED);
		delete_current_pending();
		return 0;
	}
	if (message.msg_name) {
		parsed = parse_user_address(message.msg_name, message.msg_namelen,
					    &pending->network, 1);
		if (parsed <= 0) {
			if (parsed < 0)
				increment_stat(NETWORK_STAT_USER_READ_FAILED);
			delete_current_pending();
			return 0;
		}
		pending->header.flags |= AGENT_FLAG_NETWORK_DEST_VALID;
	}
	store_pending(pending);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendmsg")
int trace_sendmsg_exit(struct trace_event_raw_sys_exit *ctx)
{
	return complete_call(AGENT_EVENT_NETWORK_UDP_SEND, (__s64)ctx->ret);
}

static __always_inline int observe_socket(struct bpf_sock_addr *ctx)
{
	struct observed_socket *storage;
	__u64 cookie;

	if (!ctx->sk)
		return 1;
	storage = bpf_sk_storage_get(&observed_sockets, ctx->sk, 0,
				     BPF_SK_STORAGE_GET_F_CREATE);
	if (!storage)
		return 1;
	cookie = bpf_get_socket_cookie(ctx);
	if (cookie)
		storage->socket_cookie = cookie;
	storage->network_namespace_cookie = bpf_get_netns_cookie(ctx);
	storage->cgroup_id = bpf_get_current_cgroup_id();
	return 1;
}

SEC("cgroup/connect4")
int enrich_connect4(struct bpf_sock_addr *ctx)
{
	return observe_socket(ctx);
}

SEC("cgroup/connect6")
int enrich_connect6(struct bpf_sock_addr *ctx)
{
	return observe_socket(ctx);
}

SEC("cgroup/bind4")
int enrich_bind4(struct bpf_sock_addr *ctx)
{
	return observe_socket(ctx);
}

SEC("cgroup/bind6")
int enrich_bind6(struct bpf_sock_addr *ctx)
{
	return observe_socket(ctx);
}

SEC("cgroup/sendmsg4")
int enrich_sendmsg4(struct bpf_sock_addr *ctx)
{
	return observe_socket(ctx);
}

SEC("cgroup/sendmsg6")
int enrich_sendmsg6(struct bpf_sock_addr *ctx)
{
	return observe_socket(ctx);
}

static __always_inline int sockops_state_enabled(__u16 remote_port,
						  __u64 *rate_interval_ns,
						  __u64 *rate_burst_ns)
{
	const struct agent_config *config;
	__u32 key = 0;

	config = bpf_map_lookup_elem(&network_config_map, &key);
	if (!config || !(config->network_flags &
			 AGENT_NETWORK_CONFIG_SOCKOPS_STATE))
		return 0;
	if (!(config->event_mask &
	      AGENT_EVENT_BIT(AGENT_EVENT_NETWORK_TCP_STATE)))
		return 0;
	/* State callbacks are not guaranteed to run in the owner task context. */
	if (config->target_tgid || config->target_cgroup_id)
		return 0;
	if (config->network_protocol && config->network_protocol != IPPROTO_TCP)
		return 0;
	if (config->network_destination_port &&
	    config->network_destination_port != remote_port)
		return 0;
	*rate_interval_ns = config->network_rate_interval_ns;
	*rate_burst_ns = config->network_rate_burst_ns;
	return 1;
}

static __always_inline void emit_sockops_state(
	struct bpf_sock_ops *ctx, struct observed_socket *observed,
	__u16 old_state, __u16 new_state, __u64 rate_interval_ns,
	__u64 rate_burst_ns)
{
	struct agent_network_payload *network;
	struct agent_event *event;
	__u16 remote_port;

	if (!rate_limit_allows(observed->cgroup_id, 0,
				       AGENT_EVENT_NETWORK_TCP_STATE, IPPROTO_TCP,
				       (__u16)bpf_ntohl(ctx->remote_port),
				       rate_interval_ns, rate_burst_ns)) {
		increment_stat(NETWORK_STAT_RATE_LIMITED);
		return;
	}
	remote_port = (__u16)bpf_ntohl(ctx->remote_port);
	event = bpf_ringbuf_reserve(&network_events,
				    AGENT_NETWORK_EVENT_SIZE, 0);
	if (!event) {
		increment_stat(NETWORK_STAT_RINGBUF_LOST);
		return;
	}
	__builtin_memset(event, 0, AGENT_NETWORK_EVENT_SIZE);
	fill_sockops_header(&event->header, observed->cgroup_id);
	event->header.flags |= AGENT_FLAG_NETWORK_PROCESS_UNCERTAIN |
		AGENT_FLAG_NETWORK_SOURCE_VALID |
		AGENT_FLAG_NETWORK_DEST_VALID |
		AGENT_FLAG_NETWORK_SOCKET_VALID;
	network = &event->data.network;
	network->address_family = ctx->family;
	network->protocol = IPPROTO_TCP;
	network->socket_type = SOCK_STREAM;
	network->source_port = ctx->local_port;
	network->destination_port = remote_port;
	network->old_state = old_state;
	network->new_state = new_state;
	network->socket_cookie = observed->socket_cookie;
	network->network_namespace_cookie = observed->network_namespace_cookie;
	if (network->socket_cookie)
		event->header.flags |= AGENT_FLAG_NETWORK_COOKIE_VALID;
	if (network->network_namespace_cookie)
		event->header.flags |= AGENT_FLAG_NETWORK_NETNS_COOKIE_VALID;

	if (ctx->family == AF_INET) {
		__u32 local = ctx->local_ip4;
		__u32 remote = ctx->remote_ip4;

		__builtin_memcpy(network->source_address, &local, 4);
		__builtin_memcpy(network->destination_address, &remote, 4);
	} else {
		__u32 local0 = ctx->local_ip6[0];
		__u32 local1 = ctx->local_ip6[1];
		__u32 local2 = ctx->local_ip6[2];
		__u32 local3 = ctx->local_ip6[3];
		__u32 remote0 = ctx->remote_ip6[0];
		__u32 remote1 = ctx->remote_ip6[1];
		__u32 remote2 = ctx->remote_ip6[2];
		__u32 remote3 = ctx->remote_ip6[3];

		__builtin_memcpy(&network->source_address[0], &local0, 4);
		__builtin_memcpy(&network->source_address[4], &local1, 4);
		__builtin_memcpy(&network->source_address[8], &local2, 4);
		__builtin_memcpy(&network->source_address[12], &local3, 4);
		__builtin_memcpy(&network->destination_address[0], &remote0, 4);
		__builtin_memcpy(&network->destination_address[4], &remote1, 4);
		__builtin_memcpy(&network->destination_address[8], &remote2, 4);
		__builtin_memcpy(&network->destination_address[12], &remote3, 4);
	}
	bpf_ringbuf_submit(event, 0);
}

SEC("sockops")
int observe_tcp_states(struct bpf_sock_ops *ctx)
{
	struct observed_socket *observed;
	struct bpf_sock *sk;
	__u64 cookie;
	__u64 rate_interval_ns = 0;
	__u64 rate_burst_ns = 0;
	__u16 remote_port;

	sk = ctx->sk;
	remote_port = (__u16)bpf_ntohl(ctx->remote_port);
	if (!sockops_state_enabled(remote_port, &rate_interval_ns,
				   &rate_burst_ns) || !sk ||
	    (ctx->family != AF_INET && ctx->family != AF_INET6))
		return 1;

	if (ctx->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB ||
	    ctx->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
		observed = bpf_sk_storage_get(&observed_sockets, sk, 0,
					      BPF_SK_STORAGE_GET_F_CREATE);
		if (!observed)
			return 1;
		cookie = bpf_get_socket_cookie(ctx);
		if (cookie)
			observed->socket_cookie = cookie;
		observed->network_namespace_cookie = bpf_get_netns_cookie(ctx);
		bpf_sock_ops_cb_flags_set(
			ctx, ctx->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_STATE_CB_FLAG);
		emit_sockops_state(ctx, observed, 0, BPF_TCP_ESTABLISHED,
				   rate_interval_ns, rate_burst_ns);
		return 1;
	}

	if (ctx->op != BPF_SOCK_OPS_STATE_CB)
		return 1;
	observed = bpf_sk_storage_get(&observed_sockets, sk, 0, 0);
	if (!observed)
		return 1;
	emit_sockops_state(ctx, observed, ctx->args[0], ctx->args[1],
			   rate_interval_ns, rate_burst_ns);
	if (ctx->args[1] == BPF_TCP_CLOSE)
		bpf_sk_storage_delete(&observed_sockets, sk);
	return 1;
}

static __always_inline int tcp_state_event_enabled(
	__u16 destination_port, __u16 protocol, __u64 *rate_interval_ns,
	__u64 *rate_burst_ns)
{
	const struct agent_config *config;
	__u32 key = 0;

	config = bpf_map_lookup_elem(&network_config_map, &key);
	if (!config || !(config->event_mask &
			 AGENT_EVENT_BIT(AGENT_EVENT_NETWORK_TCP_STATE)))
		return 0;
	if (config->network_flags & AGENT_NETWORK_CONFIG_SOCKOPS_STATE)
		return 0;
	/* State callbacks are not guaranteed to run in the socket owner's task. */
	if (config->target_tgid || config->target_cgroup_id)
		return 0;
	if (config->network_protocol && config->network_protocol != protocol)
		return 0;
	if (config->network_destination_port &&
	    config->network_destination_port != destination_port)
		return 0;
	*rate_interval_ns = config->network_rate_interval_ns;
	*rate_burst_ns = config->network_rate_burst_ns;
	return 1;
}

SEC("tp/sock/inet_sock_set_state")
int trace_tcp_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	struct agent_network_payload *network;
	struct agent_event *event;
	struct sock *sk;
	struct net *net;
	__u64 pid_tgid;
	__u64 rate_interval_ns = 0;
	__u64 rate_burst_ns = 0;
	__s64 cookie;

	if (ctx->protocol != IPPROTO_TCP ||
	    (ctx->family != AF_INET && ctx->family != AF_INET6))
		return 0;
	if (!tcp_state_event_enabled(ctx->dport, ctx->protocol,
				     &rate_interval_ns, &rate_burst_ns))
		return 0;
	if (!rate_limit_allows(bpf_get_current_cgroup_id(), 0,
				       AGENT_EVENT_NETWORK_TCP_STATE, ctx->protocol,
				       ctx->dport,
				       rate_interval_ns, rate_burst_ns)) {
		increment_stat(NETWORK_STAT_RATE_LIMITED);
		return 0;
	}

	event = bpf_ringbuf_reserve(&network_events,
				    AGENT_NETWORK_EVENT_SIZE, 0);
	if (!event) {
		increment_stat(NETWORK_STAT_RINGBUF_LOST);
		return 0;
	}
	__builtin_memset(event, 0, AGENT_NETWORK_EVENT_SIZE);
	pid_tgid = bpf_get_current_pid_tgid();
	fill_common_header(&event->header, AGENT_EVENT_NETWORK_TCP_STATE,
			   (__u32)pid_tgid, pid_tgid >> 32,
			   bpf_get_current_cgroup_id());
	event->header.flags |= AGENT_FLAG_NETWORK_PROCESS_UNCERTAIN |
		AGENT_FLAG_NETWORK_SOURCE_VALID |
		AGENT_FLAG_NETWORK_DEST_VALID |
		AGENT_FLAG_NETWORK_SOCKET_VALID;
	network = &event->data.network;
	network->address_family = ctx->family;
	network->protocol = ctx->protocol;
	network->source_port = ctx->sport;
	network->destination_port = ctx->dport;
	network->old_state = ctx->oldstate;
	network->new_state = ctx->newstate;

	if (ctx->family == AF_INET) {
		bpf_probe_read_kernel(network->source_address, 4, ctx->saddr);
		bpf_probe_read_kernel(network->destination_address, 4, ctx->daddr);
	} else {
		bpf_probe_read_kernel(network->source_address, 16, ctx->saddr_v6);
		bpf_probe_read_kernel(network->destination_address, 16,
				      ctx->daddr_v6);
	}

	sk = (struct sock *)ctx->skaddr;
	if (sk) {
		if (bpf_core_field_exists(sk->__sk_common.skc_cookie.counter)) {
			cookie = BPF_CORE_READ(sk, __sk_common.skc_cookie.counter);
			if (cookie > 0) {
				network->socket_cookie = cookie;
				event->header.flags |=
					AGENT_FLAG_NETWORK_COOKIE_VALID;
			}
		}
		net = BPF_CORE_READ(sk, __sk_common.skc_net.net);
		if (net)
			network->network_namespace_id = BPF_CORE_READ(net, ns.inum);
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
