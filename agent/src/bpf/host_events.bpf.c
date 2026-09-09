// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "agent_events.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 * 1024 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct agent_config);
} agent_config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, AGENT_EVENT_TYPE_MAX);
	__type(key, __u32);
	__type(value, __u64);
} lost_events SEC(".maps");

/* sys_exit does not expose the syscall ID, so remember it at sys_enter. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 32768);
	__type(key, __u64);
	__type(value, __u32);
} inflight_syscalls SEC(".maps");

static __always_inline void account_lost(__u32 type)
{
	__u64 *count;

	if (type >= AGENT_EVENT_TYPE_MAX)
		return;

	count = bpf_map_lookup_elem(&lost_events, &type);
	if (count)
		(*count)++;
}

static __always_inline int target_matches(const struct agent_config *cfg,
					   __u32 tgid, __u64 cgroup_id)
{
	struct bpf_pidns_info namespace_ids = {};
	__u32 filter_tgid = tgid;
	int namespace_matches = 1;

	if (cfg->pidns_inode) {
		namespace_matches = 0;
		if (!bpf_get_ns_current_pid_tgid(cfg->pidns_device,
						 cfg->pidns_inode,
						 &namespace_ids,
						 sizeof(namespace_ids))) {
			namespace_matches = 1;
			filter_tgid = namespace_ids.tgid;
		}
	}

	if (cfg->exclude_tgid && namespace_matches &&
	    cfg->exclude_tgid == filter_tgid)
		return 0;

	if (cfg->target_tgid &&
	    (!namespace_matches || cfg->target_tgid != filter_tgid))
		return 0;

	if (cfg->target_cgroup_id && cfg->target_cgroup_id != cgroup_id)
		return 0;

	return 1;
}

static __always_inline int event_enabled(__u32 type)
{
	const struct agent_config *cfg;
	__u64 pid_tgid;
	__u64 cgroup_id;
	__u32 tgid;
	__u32 key = 0;

	cfg = bpf_map_lookup_elem(&agent_config_map, &key);
	if (!cfg || !(cfg->event_mask & AGENT_EVENT_BIT(type)))
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = pid_tgid >> 32;
	cgroup_id = bpf_get_current_cgroup_id();
	return target_matches(cfg, tgid, cgroup_id);
}

static __always_inline void fill_common(struct agent_event *event, __u32 type)
{
	const struct agent_config *cfg;
	struct bpf_pidns_info namespace_ids = {};
	struct task_struct *task;
	__u64 pid_tgid;
	__u64 uid_gid;
	__u32 key = 0;

	__builtin_memset(event, 0, sizeof(*event));

	pid_tgid = bpf_get_current_pid_tgid();
	uid_gid = bpf_get_current_uid_gid();
	task = (struct task_struct *)bpf_get_current_task();

	event->header.timestamp_ns = bpf_ktime_get_ns();
	event->header.cgroup_id = bpf_get_current_cgroup_id();
	event->header.pid = (__u32)pid_tgid;
	event->header.tgid = pid_tgid >> 32;
	event->header.namespace_pid = event->header.pid;
	event->header.namespace_tgid = event->header.tgid;
	event->header.uid = (__u32)uid_gid;
	event->header.gid = uid_gid >> 32;
	event->header.cpu = bpf_get_smp_processor_id();
	event->header.size = sizeof(*event);
	event->header.version = AGENT_SCHEMA_VERSION;
	event->header.type = type;
	cfg = bpf_map_lookup_elem(&agent_config_map, &key);
	if (cfg && cfg->pidns_inode &&
	    !bpf_get_ns_current_pid_tgid(cfg->pidns_device, cfg->pidns_inode,
					 &namespace_ids, sizeof(namespace_ids))) {
		event->header.namespace_pid = namespace_ids.pid;
		event->header.namespace_tgid = namespace_ids.tgid;
	}

	if (task) {
		event->header.ppid = BPF_CORE_READ(task, real_parent, tgid);

		if (bpf_core_field_exists(task->start_boottime))
			event->header.task_start_ns =
				BPF_CORE_READ(task, start_boottime);
		else if (bpf_core_field_exists(task->start_time))
			event->header.task_start_ns =
				BPF_CORE_READ(task, start_time);
	}

	bpf_get_current_comm(event->header.comm, sizeof(event->header.comm));
}

static __always_inline struct agent_event *reserve_event(__u32 type)
{
	struct agent_event *event;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		account_lost(type);
		return 0;
	}

	fill_common(event, type);
	return event;
}

SEC("tp/sched/sched_process_fork")
int handle_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	struct agent_event *event;

	if (!event_enabled(AGENT_EVENT_PROCESS_FORK))
		return 0;

	event = reserve_event(AGENT_EVENT_PROCESS_FORK);
	if (!event)
		return 0;

	event->data.process.parent_pid = ctx->parent_pid;
	event->data.process.child_pid = ctx->child_pid;

	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct agent_event *event;
	unsigned int filename_offset;
	long copied;

	if (!event_enabled(AGENT_EVENT_PROCESS_EXEC))
		return 0;

	event = reserve_event(AGENT_EVENT_PROCESS_EXEC);
	if (!event)
		return 0;

	event->data.process.parent_pid = event->header.ppid;
	event->data.process.child_pid = ctx->pid;
	filename_offset = ctx->__data_loc_filename & 0xffff;
	copied = bpf_probe_read_str(event->data.process.filename,
				    sizeof(event->data.process.filename),
				    (void *)ctx + filename_offset);
	if (copied < 0)
		event->header.flags |= AGENT_FLAG_PATH_UNAVAILABLE;
	else if (copied == sizeof(event->data.process.filename))
		event->header.flags |= AGENT_FLAG_PATH_TRUNCATED;

	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
	struct task_struct *task;
	struct agent_event *event;
	__u64 pid_tgid;

	(void)ctx;
	pid_tgid = bpf_get_current_pid_tgid();
	/* Emit process exits, not every thread exit. */
	if ((__u32)pid_tgid != pid_tgid >> 32)
		return 0;

	if (!event_enabled(AGENT_EVENT_PROCESS_EXIT))
		return 0;

	event = reserve_event(AGENT_EVENT_PROCESS_EXIT);
	if (!event)
		return 0;

	task = (struct task_struct *)bpf_get_current_task();
	event->data.process.parent_pid = event->header.ppid;
	event->data.process.child_pid = event->header.pid;
	if (task) {
		event->data.process.exit_code = BPF_CORE_READ(task, exit_code);
		event->header.result = event->data.process.exit_code;
	}

	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("raw_tracepoint/sys_enter")
int handle_syscall_enter(struct bpf_raw_tracepoint_args *ctx)
{
	struct agent_event *event;
	__u64 pid_tgid;
	__u32 syscall_id;
	int emit_enter;
	int emit_exit;

	emit_enter = event_enabled(AGENT_EVENT_SYSCALL_ENTER);
	emit_exit = event_enabled(AGENT_EVENT_SYSCALL_EXIT);
	if (!emit_enter && !emit_exit)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	syscall_id = (__u32)ctx->args[1];

	if (emit_exit)
		bpf_map_update_elem(&inflight_syscalls, &pid_tgid, &syscall_id,
				    BPF_ANY);

	if (!emit_enter)
		return 0;

	event = reserve_event(AGENT_EVENT_SYSCALL_ENTER);
	if (!event)
		return 0;

	event->data.syscall.syscall_id = syscall_id;
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("raw_tracepoint/sys_exit")
int handle_syscall_exit(struct bpf_raw_tracepoint_args *ctx)
{
	struct agent_event *event;
	__u64 pid_tgid;
	__u32 *syscall_id;
	__u32 id = (__u32)-1;
	__s64 return_value;

	if (!event_enabled(AGENT_EVENT_SYSCALL_EXIT))
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	return_value = (__s64)ctx->args[1];
	syscall_id = bpf_map_lookup_elem(&inflight_syscalls, &pid_tgid);
	if (syscall_id)
		id = *syscall_id;

	event = reserve_event(AGENT_EVENT_SYSCALL_EXIT);
	if (!event) {
		bpf_map_delete_elem(&inflight_syscalls, &pid_tgid);
		return 0;
	}

	if (!syscall_id)
		event->header.flags |= AGENT_FLAG_MISSING_ENTRY;
	event->header.result = (__s32)return_value;
	event->data.syscall.syscall_id = id;
	event->data.syscall.return_value = return_value;
	bpf_map_delete_elem(&inflight_syscalls, &pid_tgid);

	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(handle_file_open, struct file *file, int ret)
{
	struct agent_event *event;
	struct inode *inode;
	struct super_block *superblock;
	long path_length;

	(void)ctx;
	if (!event_enabled(AGENT_EVENT_FILE_OPEN))
		return ret;

	event = reserve_event(AGENT_EVENT_FILE_OPEN);
	if (!event)
		return ret;

	event->header.result = ret;
	event->data.file.operation = AGENT_FILE_OPEN;
	if (!file) {
		event->header.flags |= AGENT_FLAG_PATH_UNAVAILABLE;
		goto submit;
	}

	event->data.file.open_flags = BPF_CORE_READ(file, f_flags);
	event->data.file.mode = BPF_CORE_READ(file, f_mode);
	inode = BPF_CORE_READ(file, f_inode);
	if (inode) {
		event->data.file.inode = BPF_CORE_READ(inode, i_ino);
		superblock = BPF_CORE_READ(inode, i_sb);
		if (superblock)
			event->data.file.device = BPF_CORE_READ(superblock, s_dev);
	}

	path_length = bpf_d_path((struct path *)&file->f_path,
				 event->data.file.path,
				 AGENT_PATH_LEN);
	if (path_length < 0)
		event->header.flags |= AGENT_FLAG_PATH_UNAVAILABLE;
	else if (path_length == AGENT_PATH_LEN)
		event->header.flags |= AGENT_FLAG_PATH_TRUNCATED;

submit:
	bpf_ringbuf_submit(event, 0);
	/* This sensor observes only; always preserve the previous LSM decision. */
	return ret;
}

SEC("lsm/inode_unlink")
int BPF_PROG(handle_file_unlink, struct inode *dir, struct dentry *dentry,
	     int ret)
{
	struct agent_event *event;
	struct inode *inode;
	struct super_block *superblock;
	const unsigned char *name;
	long copied;

	(void)ctx;
	if (!event_enabled(AGENT_EVENT_FILE_UNLINK))
		return ret;

	event = reserve_event(AGENT_EVENT_FILE_UNLINK);
	if (!event)
		return ret;

	event->header.result = ret;
	event->header.flags |= AGENT_FLAG_PARTIAL_PATH;
	event->data.file.operation = AGENT_FILE_UNLINK;

	if (dir) {
		event->data.file.directory_inode = BPF_CORE_READ(dir, i_ino);
		superblock = BPF_CORE_READ(dir, i_sb);
		if (superblock)
			event->data.file.device = BPF_CORE_READ(superblock, s_dev);
	}

	if (!dentry) {
		event->header.flags |= AGENT_FLAG_PATH_UNAVAILABLE;
		goto submit;
	}

	inode = BPF_CORE_READ(dentry, d_inode);
	if (inode)
		event->data.file.inode = BPF_CORE_READ(inode, i_ino);

	name = BPF_CORE_READ(dentry, d_name.name);
	if (!name) {
		event->header.flags |= AGENT_FLAG_PATH_UNAVAILABLE;
		goto submit;
	}

	copied = bpf_probe_read_kernel_str(event->data.file.path,
					   sizeof(event->data.file.path), name);
	if (copied < 0)
		event->header.flags |= AGENT_FLAG_PATH_UNAVAILABLE;
	else if (copied == sizeof(event->data.file.path))
		event->header.flags |= AGENT_FLAG_PATH_TRUNCATED;

submit:
	bpf_ringbuf_submit(event, 0);
	return ret;
}
