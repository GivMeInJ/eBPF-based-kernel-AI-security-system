/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef AGENT_EVENTS_H
#define AGENT_EVENTS_H

/* vmlinux.h already provides the Linux integer types for BPF programs. */
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define AGENT_SCHEMA_VERSION 1
#define AGENT_WIRE_VERSION 1
#define AGENT_COMM_LEN 16
#define AGENT_PATH_LEN 256

enum agent_event_type {
	AGENT_EVENT_UNSPEC = 0,
	AGENT_EVENT_PROCESS_FORK = 1,
	AGENT_EVENT_PROCESS_EXEC = 2,
	AGENT_EVENT_PROCESS_EXIT = 3,
	AGENT_EVENT_SYSCALL_ENTER = 4,
	AGENT_EVENT_SYSCALL_EXIT = 5,
	AGENT_EVENT_FILE_OPEN = 6,
	AGENT_EVENT_FILE_UNLINK = 7,
	AGENT_EVENT_NETWORK_CONNECT = 8,
	AGENT_EVENT_NETWORK_BIND = 9,
	AGENT_EVENT_NETWORK_LISTEN = 10,
	AGENT_EVENT_NETWORK_ACCEPT = 11,
	AGENT_EVENT_NETWORK_UDP_SEND = 12,
	AGENT_EVENT_NETWORK_TCP_STATE = 13,
	AGENT_EVENT_HEALTH = 14,
	AGENT_EVENT_TYPE_MAX = 15,
};

#define AGENT_EVENT_BIT(type) (1ULL << (type))

#define AGENT_NETWORK_EVENT_MASK_ALL \
	(AGENT_EVENT_BIT(AGENT_EVENT_NETWORK_CONNECT) | \
	 AGENT_EVENT_BIT(AGENT_EVENT_NETWORK_BIND) | \
	 AGENT_EVENT_BIT(AGENT_EVENT_NETWORK_LISTEN) | \
	 AGENT_EVENT_BIT(AGENT_EVENT_NETWORK_ACCEPT) | \
	 AGENT_EVENT_BIT(AGENT_EVENT_NETWORK_UDP_SEND) | \
	 AGENT_EVENT_BIT(AGENT_EVENT_NETWORK_TCP_STATE))

#define AGENT_NETWORK_EVENT_MASK_DEFAULT \
	(AGENT_NETWORK_EVENT_MASK_ALL & \
	 ~AGENT_EVENT_BIT(AGENT_EVENT_NETWORK_TCP_STATE))

enum agent_event_flags {
	AGENT_FLAG_PATH_UNAVAILABLE = 1U << 0,
	AGENT_FLAG_PATH_TRUNCATED = 1U << 1,
	AGENT_FLAG_PARTIAL_PATH = 1U << 2,
	AGENT_FLAG_MISSING_ENTRY = 1U << 3,
	AGENT_FLAG_NETWORK_DEST_VALID = 1U << 4,
	AGENT_FLAG_NETWORK_SOURCE_VALID = 1U << 5,
	AGENT_FLAG_NETWORK_SOCKET_VALID = 1U << 6,
	AGENT_FLAG_NETWORK_COOKIE_VALID = 1U << 7,
	AGENT_FLAG_NETWORK_NETNS_COOKIE_VALID = 1U << 8,
	AGENT_FLAG_NETWORK_PROCESS_UNCERTAIN = 1U << 9,
	AGENT_FLAG_USERSPACE_GENERATED = 1U << 10,
};

enum agent_file_operation {
	AGENT_FILE_OPEN = 1,
	AGENT_FILE_UNLINK = 2,
};

enum agent_network_config_flags {
	AGENT_NETWORK_CONFIG_SOCKOPS_STATE = 1U << 0,
};

/*
 * One array-map entry controls the sensors without requiring a reload.
 * A zero target field means "all targets". Syscall events should normally be
 * enabled only with a target_tgid or target_cgroup_id because of their volume.
 */
struct agent_config {
	__u64 event_mask;
	__u64 target_cgroup_id;
	__u64 pidns_device;
	__u64 pidns_inode;
	__u32 target_tgid;
	__u32 exclude_tgid;
	__u16 network_destination_port;
	__u8 network_protocol;
	__u8 network_flags;
	__u32 network_padding;
	__u64 network_rate_interval_ns;
	__u64 network_rate_burst_ns;
};

struct agent_event_header {
	__u64 timestamp_ns;
	__u64 cgroup_id;
	__u64 task_start_ns;

	__u32 pid;
	__u32 tgid;
	__u32 namespace_pid;
	__u32 namespace_tgid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	__u32 cpu;

	__s32 result;
	__u32 size;
	__u32 flags;
	__u16 version;
	__u16 type;

	char comm[AGENT_COMM_LEN];
};

struct agent_process_payload {
	__u32 parent_pid;
	__u32 child_pid;
	__s32 exit_code;
	__u32 reserved;
	char filename[AGENT_PATH_LEN];
};

struct agent_syscall_payload {
	__u32 syscall_id;
	__u32 reserved;
	__s64 return_value;
};

struct agent_file_payload {
	__u64 inode;
	__u64 directory_inode;
	__u32 device;
	__u32 open_flags;
	__u32 mode;
	__u32 operation;
	char path[AGENT_PATH_LEN];
};

/*
 * Addresses are stored as network-order bytes. IPv4 uses the first four
 * bytes; address_family tells consumers how many bytes to interpret.
 * Ports are stored in host byte order.
 */
struct agent_network_payload {
	__u64 duration_ns;
	__u64 network_namespace_id;
	__u64 network_namespace_cookie;
	__u64 socket_cookie;
	__s64 return_value;
	__u64 bytes_requested;
	__u32 socket_fd;
	__s32 backlog;
	__u32 source_scope_id;
	__u32 destination_scope_id;
	__u16 address_family;
	__u16 socket_type;
	__u16 source_port;
	__u16 destination_port;
	__u16 old_state;
	__u16 new_state;
	__u8 protocol;
	__u8 reserved[3];
	__u8 source_address[16];
	__u8 destination_address[16];
};

/* Periodic Collector health information delivered through the event stream. */
struct agent_health_payload {
	__u64 writer_queue_dropped;
	__u64 writer_priority_dropped;
	__u64 kernel_ringbuf_lost;
	__u64 network_filtered;
	__u64 network_rate_limited;
};

struct agent_event {
	struct agent_event_header header;
	union {
		struct agent_process_payload process;
		struct agent_syscall_payload syscall;
		struct agent_file_payload file;
		struct agent_network_payload network;
		struct agent_health_payload health;
	} data;
};

/* payload_size is little-endian; payload contains header.size native ABI bytes. */
struct agent_wire_frame_header {
	__u8 magic[4]; /* "EBPF" */
	__u8 wire_version;
	__u8 little_endian;
	__u16 reserved;
	__u32 payload_size;
};

#define AGENT_NETWORK_EVENT_SIZE \
	(__builtin_offsetof(struct agent_event, data.network) + \
	 sizeof(struct agent_network_payload))

#define AGENT_HEALTH_EVENT_SIZE \
	(__builtin_offsetof(struct agent_event, data.health) + \
	 sizeof(struct agent_health_payload))

#endif /* AGENT_EVENTS_H */
