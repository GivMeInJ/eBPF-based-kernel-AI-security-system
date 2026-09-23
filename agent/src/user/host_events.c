// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#define _GNU_SOURCE
#include <errno.h>
#include <endian.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <linux/openat2.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "agent_events.h"
#include "host_events.skel.h"
#include "server.skel.h"

_Static_assert(sizeof(struct agent_event_header) == 88,
	       "schema v1 event header layout changed");
_Static_assert(sizeof(struct agent_network_payload) == 112,
		       "schema v1 network payload layout changed");
_Static_assert(sizeof(struct agent_health_payload) == 40,
		       "schema v1 health payload layout changed");
_Static_assert(sizeof(struct agent_process_payload) == 272,
	       "schema v1 process payload layout changed");
_Static_assert(sizeof(struct agent_syscall_payload) == 16,
	       "schema v1 syscall payload layout changed");
_Static_assert(sizeof(struct agent_file_payload) == 288,
	       "schema v1 file payload layout changed");
_Static_assert(sizeof(struct agent_event) == 376,
	       "schema v1 full event layout changed");
_Static_assert(AGENT_NETWORK_EVENT_SIZE == 200,
		       "schema v1 network event layout changed");
_Static_assert(AGENT_HEALTH_EVENT_SIZE == 128,
		       "schema v1 health event layout changed");
_Static_assert(sizeof(struct agent_wire_frame_header) == 12,
	       "wire frame header layout changed");

static volatile sig_atomic_t stop;

#define NETWORK_CGROUP_PROGRAM_COUNT 7
#define MAX_RING_BUFFER_BYTES (64U * 1024U * 1024U)
#define MAX_QUEUE_CAPACITY 65536U
#define MAX_RATE_MAP_ENTRIES 65536U
#define HEALTH_INTERVAL_NS 1000000000ULL
#define NETWORK_STAT_RINGBUF_LOST_INDEX 2U
#define NETWORK_STAT_FILTERED_INDEX 4U
#define NETWORK_STAT_RATE_LIMITED_INDEX 5U

enum output_format {
	OUTPUT_NDJSON = 0,
	OUTPUT_BINARY = 1,
};

struct event_queue;

struct reader_state {
	FILE *output;
	uint64_t received[AGENT_EVENT_TYPE_MAX];
	uint64_t unflushed_events;
	uint64_t last_flush_ns;
	enum output_format format;
	atomic_int output_error;
	struct event_queue *queue;
};

struct queued_event {
	size_t size;
	unsigned char data[sizeof(struct agent_event)];
};

struct event_queue {
	struct queued_event *events;
	struct reader_state *reader;
	size_t capacity;
	size_t head;
	size_t tail;
	size_t count;
	size_t priority_reserve;
	atomic_uint_fast64_t dropped;
	atomic_uint_fast64_t priority_dropped;
	pthread_mutex_t lock;
	pthread_cond_t not_empty;
	pthread_t writer;
	bool stopping;
	bool started;
};

struct options {
	const char *output_path;
	uint64_t target_cgroup_id;
	uint64_t ring_buffer_bytes;
	uint64_t network_event_mask;
	uint32_t target_tgid;
	uint32_t network_rate;
	uint32_t network_burst;
	uint32_t queue_capacity;
	uint32_t rate_map_entries;
	uint16_t network_port;
	uint8_t network_protocol;
	uid_t run_uid;
	gid_t run_gid;
	bool enable_syscalls;
	bool syscalls_enter_only;
	bool enable_files;
	bool enable_cgroup_hooks;
	bool self_test;
	bool retain_privileges;
	bool run_as_set;
	bool allow_special_output;
	const char *cgroup_path;
	enum output_format format;
};

static void handle_signal(int signo)
{
	(void)signo;
	stop = 1;
}

static int bump_memlock_limit(void)
{
	const struct rlimit limit = { RLIM_INFINITY, RLIM_INFINITY };

	return setrlimit(RLIMIT_MEMLOCK, &limit);
}

static const char *event_type_name(uint16_t type)
{
	switch (type) {
	case AGENT_EVENT_PROCESS_FORK:
		return "PROCESS_FORK";
	case AGENT_EVENT_PROCESS_EXEC:
		return "PROCESS_EXEC";
	case AGENT_EVENT_PROCESS_EXIT:
		return "PROCESS_EXIT";
	case AGENT_EVENT_SYSCALL_ENTER:
		return "SYSCALL_ENTER";
	case AGENT_EVENT_SYSCALL_EXIT:
		return "SYSCALL_EXIT";
	case AGENT_EVENT_FILE_OPEN:
		return "FILE_OPEN";
	case AGENT_EVENT_FILE_UNLINK:
		return "FILE_UNLINK";
	case AGENT_EVENT_NETWORK_CONNECT:
		return "NETWORK_CONNECT";
	case AGENT_EVENT_NETWORK_BIND:
		return "NETWORK_BIND";
	case AGENT_EVENT_NETWORK_LISTEN:
		return "NETWORK_LISTEN";
	case AGENT_EVENT_NETWORK_ACCEPT:
		return "NETWORK_ACCEPT";
	case AGENT_EVENT_NETWORK_UDP_SEND:
		return "NETWORK_UDP_SEND";
	case AGENT_EVENT_NETWORK_TCP_STATE:
		return "NETWORK_TCP_STATE";
	case AGENT_EVENT_HEALTH:
		return "HEALTH";
	default:
		return "UNKNOWN";
	}
}

static size_t valid_utf8_length(const unsigned char *value, size_t remaining)
{
	unsigned char first;
	unsigned char second;
	size_t length;
	size_t index;

	if (!remaining)
		return 0;
	first = value[0];
	if (first < 0x80)
		return 1;
	if (first >= 0xc2 && first <= 0xdf)
		length = 2;
	else if (first >= 0xe0 && first <= 0xef)
		length = 3;
	else if (first >= 0xf0 && first <= 0xf4)
		length = 4;
	else
		return 0;
	if (remaining < length)
		return 0;

	second = value[1];
	if ((second & 0xc0) != 0x80)
		return 0;
	if (first == 0xe0 && second < 0xa0)
		return 0;
	if (first == 0xed && second > 0x9f)
		return 0;
	if (first == 0xf0 && second < 0x90)
		return 0;
	if (first == 0xf4 && second > 0x8f)
		return 0;
	for (index = 2; index < length; index++) {
		if ((value[index] & 0xc0) != 0x80)
			return 0;
	}
	return length;
}

static void write_json_string(FILE *output, const char *value, size_t max_len)
{
	size_t i;

	fputc('"', output);
	for (i = 0; i < max_len && value[i] != '\0'; i++) {
		unsigned char ch = (unsigned char)value[i];

		switch (ch) {
		case '"':
			fputs("\\\"", output);
			break;
		case '\\':
			fputs("\\\\", output);
			break;
		case '\b':
			fputs("\\b", output);
			break;
		case '\f':
			fputs("\\f", output);
			break;
		case '\n':
			fputs("\\n", output);
			break;
		case '\r':
			fputs("\\r", output);
			break;
		case '\t':
			fputs("\\t", output);
			break;
		default: {
			size_t sequence_length;

			if (ch < 0x20)
				fprintf(output, "\\u%04x", ch);
			else if (ch < 0x80)
				fputc(ch, output);
			else {
				sequence_length = valid_utf8_length(
					(const unsigned char *)&value[i], max_len - i);
				if (sequence_length) {
					fwrite(&value[i], sequence_length, 1, output);
					i += sequence_length - 1;
				} else {
					/* Preserve an invalid byte without producing invalid JSON. */
					fprintf(output, "\\u%04x", ch);
				}
			}
			break;
		}
		}
	}
	fputc('"', output);
}

static size_t minimum_event_size(uint16_t type)
{
	switch (type) {
	case AGENT_EVENT_PROCESS_FORK:
	case AGENT_EVENT_PROCESS_EXEC:
	case AGENT_EVENT_PROCESS_EXIT:
		return offsetof(struct agent_event, data.process) +
		       sizeof(struct agent_process_payload);
	case AGENT_EVENT_SYSCALL_ENTER:
	case AGENT_EVENT_SYSCALL_EXIT:
		return offsetof(struct agent_event, data.syscall) +
		       sizeof(struct agent_syscall_payload);
	case AGENT_EVENT_FILE_OPEN:
	case AGENT_EVENT_FILE_UNLINK:
		return offsetof(struct agent_event, data.file) +
		       sizeof(struct agent_file_payload);
	case AGENT_EVENT_NETWORK_CONNECT:
	case AGENT_EVENT_NETWORK_BIND:
	case AGENT_EVENT_NETWORK_LISTEN:
	case AGENT_EVENT_NETWORK_ACCEPT:
	case AGENT_EVENT_NETWORK_UDP_SEND:
	case AGENT_EVENT_NETWORK_TCP_STATE:
		return AGENT_NETWORK_EVENT_SIZE;
	case AGENT_EVENT_HEALTH:
		return AGENT_HEALTH_EVENT_SIZE;
	default:
		return 0;
	}
}

static bool event_record_valid(const struct agent_event *event, size_t data_size)
{
	size_t minimum;

	if (data_size < sizeof(event->header))
		return false;
	minimum = minimum_event_size(event->header.type);
	return minimum && event->header.version == AGENT_SCHEMA_VERSION &&
	       event->header.size >= minimum && event->header.size <= data_size &&
	       event->header.size <= sizeof(*event);
}

static int write_binary_event(FILE *output, const struct agent_event *event)
{
	struct agent_wire_frame_header frame = {
		.magic = { 'E', 'B', 'P', 'F' },
		.wire_version = AGENT_WIRE_VERSION,
		.little_endian = 1,
		.payload_size = htole32(event->header.size),
	};
	unsigned char buffer[sizeof(frame) + sizeof(*event)];
	size_t total = sizeof(frame) + event->header.size;

	memcpy(buffer, &frame, sizeof(frame));
	memcpy(buffer + sizeof(frame), event, event->header.size);
	return fwrite(buffer, total, 1, output) == 1 ? 0 : -EIO;
}

static int write_event(void *context, void *data, size_t data_size)
{
	struct reader_state *state = context;
	const struct agent_event *event = data;
	FILE *output = state->output;

	if (data_size < sizeof(event->header)) {
		fprintf(stderr, "discarded short event: %zu bytes\n", data_size);
		return 0;
	}

	if (!event_record_valid(event, data_size)) {
		fprintf(stderr,
			"discarded incompatible event: version=%u size=%u sample=%zu\n",
			event->header.version, event->header.size, data_size);
		return 0;
	}

	if (event->header.type < AGENT_EVENT_TYPE_MAX)
		state->received[event->header.type]++;
	if (state->format == OUTPUT_BINARY) {
		state->output_error = write_binary_event(output, event);
		if (state->output_error)
			return state->output_error;
		state->unflushed_events++;
		return 0;
	}

	fputs("{\"schema_version\":", output);
	fprintf(output,
		"%u,\"event_type\":\"%s\",\"timestamp_ns\":%" PRIu64
		",\"pid\":%u,\"tgid\":%u"
		",\"namespace_pid\":%u,\"namespace_tgid\":%u,\"ppid\":%u"
		",\"uid\":%u,\"gid\":%u,\"cgroup_id\":%" PRIu64
			",\"task_start_ns\":%" PRIu64 ",\"cpu\":%u"
			",\"result\":%d,\"size\":%u,\"flags\":%u,\"comm\":",
		event->header.version, event_type_name(event->header.type),
		(uint64_t)event->header.timestamp_ns, event->header.pid,
		event->header.tgid, event->header.namespace_pid,
		event->header.namespace_tgid, event->header.ppid, event->header.uid,
		event->header.gid, (uint64_t)event->header.cgroup_id,
		(uint64_t)event->header.task_start_ns, event->header.cpu,
			event->header.result, event->header.size, event->header.flags);
	write_json_string(output, event->header.comm, sizeof(event->header.comm));

	switch (event->header.type) {
	case AGENT_EVENT_PROCESS_FORK:
		fprintf(output, ",\"parent_pid\":%u,\"child_pid\":%u",
			event->data.process.parent_pid,
			event->data.process.child_pid);
		break;
	case AGENT_EVENT_PROCESS_EXEC:
		fprintf(output,
			",\"parent_pid\":%u,\"child_pid\":%u,\"filename\":",
			event->data.process.parent_pid,
			event->data.process.child_pid);
		write_json_string(output, event->data.process.filename,
				  sizeof(event->data.process.filename));
		break;
	case AGENT_EVENT_PROCESS_EXIT:
		fprintf(output,
			",\"parent_pid\":%u,\"child_pid\":%u,\"exit_code_raw\":%d",
			event->data.process.parent_pid,
			event->data.process.child_pid,
			event->data.process.exit_code);
		break;
	case AGENT_EVENT_SYSCALL_ENTER:
		fprintf(output, ",\"syscall_id\":%u",
			event->data.syscall.syscall_id);
		break;
	case AGENT_EVENT_SYSCALL_EXIT:
		fprintf(output,
			",\"syscall_id\":%u,\"return_value\":%" PRId64,
			event->data.syscall.syscall_id,
			(int64_t)event->data.syscall.return_value);
		break;
	case AGENT_EVENT_FILE_OPEN:
	case AGENT_EVENT_FILE_UNLINK:
		fprintf(output,
			",\"operation\":%u,\"inode\":%" PRIu64
			",\"directory_inode\":%" PRIu64
			",\"device\":%u,\"open_flags\":%u,\"mode\":%u"
			",\"path\":",
			event->data.file.operation,
			(uint64_t)event->data.file.inode,
			(uint64_t)event->data.file.directory_inode,
			event->data.file.device, event->data.file.open_flags,
			event->data.file.mode);
		write_json_string(output, event->data.file.path,
				  sizeof(event->data.file.path));
		break;
	case AGENT_EVENT_NETWORK_CONNECT:
	case AGENT_EVENT_NETWORK_BIND:
	case AGENT_EVENT_NETWORK_LISTEN:
	case AGENT_EVENT_NETWORK_ACCEPT:
	case AGENT_EVENT_NETWORK_UDP_SEND:
	case AGENT_EVENT_NETWORK_TCP_STATE: {
		const struct agent_network_payload *network = &event->data.network;
		char source[INET6_ADDRSTRLEN] = {};
		char destination[INET6_ADDRSTRLEN] = {};
		int family = network->address_family;
		socklen_t address_size = family == AF_INET ? 4 : 16;

		if (family != AF_INET && family != AF_INET6)
			address_size = 0;
		if (address_size &&
		    (event->header.flags & AGENT_FLAG_NETWORK_SOURCE_VALID))
			inet_ntop(family, network->source_address, source,
				  sizeof(source));
		if (address_size &&
		    (event->header.flags & AGENT_FLAG_NETWORK_DEST_VALID))
			inet_ntop(family, network->destination_address, destination,
				  sizeof(destination));

		fprintf(output,
			",\"family\":%u,\"protocol\":%u,\"socket_type\":%u"
			",\"sockfd\":%u,\"netns_id\":%" PRIu64
			",\"netns_cookie\":%" PRIu64
			",\"socket_cookie\":%" PRIu64
			",\"duration_ns\":%" PRIu64
			",\"bytes_requested\":%" PRIu64
			",\"backlog\":%d,\"old_state\":%u,\"new_state\":%u"
			",\"src_scope_id\":%u"
			",\"dst_scope_id\":%u,\"src_ip\":",
			network->address_family, network->protocol,
			network->socket_type, network->socket_fd,
			(uint64_t)network->network_namespace_id,
			(uint64_t)network->network_namespace_cookie,
			(uint64_t)network->socket_cookie,
			(uint64_t)network->duration_ns,
			(uint64_t)network->bytes_requested, network->backlog,
			network->old_state, network->new_state,
			network->source_scope_id, network->destination_scope_id);
		if (source[0])
			write_json_string(output, source, sizeof(source));
		else
			fputs("null", output);
		fprintf(output, ",\"src_port\":%u,\"dst_ip\":",
			network->source_port);
		if (destination[0])
			write_json_string(output, destination, sizeof(destination));
		else
			fputs("null", output);
		fprintf(output, ",\"dst_port\":%u,\"retval\":%" PRId64,
			network->destination_port,
			(int64_t)network->return_value);
		break;
	}
	case AGENT_EVENT_HEALTH:
		fprintf(output,
			",\"writer_queue_dropped\":%" PRIu64
			",\"writer_priority_dropped\":%" PRIu64
			",\"kernel_ringbuf_lost\":%" PRIu64
			",\"network_filtered\":%" PRIu64
			",\"network_rate_limited\":%" PRIu64,
			(uint64_t)event->data.health.writer_queue_dropped,
			(uint64_t)event->data.health.writer_priority_dropped,
			(uint64_t)event->data.health.kernel_ringbuf_lost,
			(uint64_t)event->data.health.network_filtered,
			(uint64_t)event->data.health.network_rate_limited);
		break;
	default:
		break;
	}

	fputs("}\n", output);
	state->unflushed_events++;
	return 0;
}

static uint64_t monotonic_ns(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return 0;
	return (uint64_t)now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static int secure_open_output(const char *path, enum output_format format,
			      bool allow_special, FILE **output)
{
	const int flags = O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NONBLOCK;
	struct stat metadata;
	int descriptor = -1;
	FILE *stream;

#ifdef SYS_openat2
	{
		struct open_how how = {
			.flags = flags,
			.mode = S_IRUSR | S_IWUSR,
			.resolve = RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
		};

		descriptor = syscall(SYS_openat2, AT_FDCWD, path, &how,
				     sizeof(how));
		if (descriptor < 0 && errno != ENOSYS && errno != EINVAL &&
		    errno != E2BIG)
			return -errno;
	}
#endif
	if (descriptor < 0) {
		descriptor = open(path, flags | O_NOFOLLOW,
				  S_IRUSR | S_IWUSR);
		if (descriptor < 0)
			return -errno;
		fprintf(stderr,
			"warning: openat2 unavailable; only the final output path component is protected\n");
	}

	if (fstat(descriptor, &metadata)) {
		int error = -errno;

		close(descriptor);
		return error;
	}
	if (!S_ISREG(metadata.st_mode) &&
	    (!allow_special ||
	     (!S_ISFIFO(metadata.st_mode) && !S_ISCHR(metadata.st_mode)))) {
		close(descriptor);
		return -EINVAL;
	}
	if (!S_ISREG(metadata.st_mode) &&
	    (metadata.st_uid != geteuid() || metadata.st_nlink != 1)) {
		close(descriptor);
		return -EACCES;
	}
	if (!S_ISREG(metadata.st_mode)) {
		int status_flags = fcntl(descriptor, F_GETFL);

		if (status_flags < 0 ||
		    fcntl(descriptor, F_SETFL, status_flags & ~O_NONBLOCK)) {
			int error = -errno;

			close(descriptor);
			return error;
		}
	}
	if (S_ISREG(metadata.st_mode)) {
		if (metadata.st_nlink != 1) {
			close(descriptor);
			return -EMLINK;
		}
		if (metadata.st_uid != geteuid()) {
			close(descriptor);
			return -EACCES;
		}
		if (fchmod(descriptor, S_IRUSR | S_IWUSR)) {
			int error = -errno;

			close(descriptor);
			return error;
		}
		if (fstat(descriptor, &metadata)) {
			int error = -errno;

			close(descriptor);
			return error;
		}
		if (metadata.st_mode & (S_IRWXG | S_IRWXO)) {
			close(descriptor);
			return -EACCES;
		}
	}

	stream = fdopen(descriptor, format == OUTPUT_BINARY ? "ab" : "a");
	if (!stream) {
		int error = -errno;

		close(descriptor);
		return error;
	}
	*output = stream;
	return 0;
}

static int drop_root_privileges(uid_t uid, gid_t gid)
{
	if (geteuid() != 0)
		return 0;
	if (!uid || !gid)
		return -EINVAL;
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		return -errno;
	if (setgroups(0, NULL))
		return -errno;
	if (setresgid(gid, gid, gid))
		return -errno;
	if (setresuid(uid, uid, uid))
		return -errno;
	return 0;
}

static void flush_output(struct reader_state *state, bool force)
{
	uint64_t now = monotonic_ns();

	if (!state->unflushed_events)
		return;
	if (!force && state->unflushed_events < 256 && state->last_flush_ns &&
	    now - state->last_flush_ns < 500000000ULL)
		return;
	if (fflush(state->output))
		state->output_error = -errno;
	state->unflushed_events = 0;
	state->last_flush_ns = now;
}

static void *event_writer(void *context)
{
	struct event_queue *queue = context;
	struct queued_event event;

	for (;;) {
		pthread_mutex_lock(&queue->lock);
		while (!queue->count && !queue->stopping)
			pthread_cond_wait(&queue->not_empty, &queue->lock);
		if (!queue->count && queue->stopping) {
			pthread_mutex_unlock(&queue->lock);
			break;
		}
		event = queue->events[queue->tail];
		queue->tail = (queue->tail + 1) % queue->capacity;
		queue->count--;
		pthread_mutex_unlock(&queue->lock);

		if (write_event(queue->reader, event.data, event.size)) {
			pthread_mutex_lock(&queue->lock);
			queue->stopping = true;
			pthread_mutex_unlock(&queue->lock);
			break;
		}
		flush_output(queue->reader, false);
	}
	return NULL;
}

static int event_queue_start(struct event_queue *queue,
			     struct reader_state *reader, size_t capacity)
{
	int error;

	queue->events = calloc(capacity, sizeof(*queue->events));
	if (!queue->events)
		return -ENOMEM;
	queue->reader = reader;
	queue->capacity = capacity;
	queue->priority_reserve = capacity / 8;
	if (!queue->priority_reserve)
		queue->priority_reserve = 1;
	atomic_init(&queue->dropped, 0);
	atomic_init(&queue->priority_dropped, 0);
	error = pthread_mutex_init(&queue->lock, NULL);
	if (error)
		goto free_events;
	error = pthread_cond_init(&queue->not_empty, NULL);
	if (error)
		goto destroy_mutex;
	error = pthread_create(&queue->writer, NULL, event_writer, queue);
	if (error)
		goto destroy_condition;
	queue->started = true;
	return 0;

destroy_condition:
	pthread_cond_destroy(&queue->not_empty);
destroy_mutex:
	pthread_mutex_destroy(&queue->lock);
free_events:
	free(queue->events);
	queue->events = NULL;
	return -error;
}

static void event_queue_finish(struct event_queue *queue)
{
	if (!queue->started)
		return;
	pthread_mutex_lock(&queue->lock);
	queue->stopping = true;
	pthread_cond_signal(&queue->not_empty);
	pthread_mutex_unlock(&queue->lock);
	pthread_join(queue->writer, NULL);
	pthread_cond_destroy(&queue->not_empty);
	pthread_mutex_destroy(&queue->lock);
	free(queue->events);
	queue->events = NULL;
	queue->started = false;
}

static bool event_is_priority(uint16_t type)
{
	switch (type) {
	case AGENT_EVENT_PROCESS_EXEC:
	case AGENT_EVENT_FILE_UNLINK:
	case AGENT_EVENT_NETWORK_CONNECT:
	case AGENT_EVENT_NETWORK_BIND:
	case AGENT_EVENT_NETWORK_LISTEN:
	case AGENT_EVENT_NETWORK_ACCEPT:
	case AGENT_EVENT_HEALTH:
		return true;
	default:
		return false;
	}
}

static int enqueue_event(void *context, void *data, size_t data_size,
			 bool ignore_signal)
{
	struct reader_state *reader = context;
	struct event_queue *queue = reader->queue;
	const struct agent_event *incoming = data;
	struct queued_event *event;
	bool priority;

	if (stop && !ignore_signal)
		return -EINTR;
	if (data_size > sizeof(struct agent_event) ||
	    !event_record_valid(incoming, data_size))
		return 0;
	priority = event_is_priority(incoming->header.type);

	pthread_mutex_lock(&queue->lock);
	if (queue->stopping) {
		pthread_mutex_unlock(&queue->lock);
		return -EIO;
	}
	if (queue->count == queue->capacity ||
	    (!priority &&
	     queue->count >= queue->capacity - queue->priority_reserve)) {
		atomic_fetch_add_explicit(&queue->dropped, 1,
					 memory_order_relaxed);
		if (priority)
			atomic_fetch_add_explicit(&queue->priority_dropped, 1,
						 memory_order_relaxed);
		pthread_mutex_unlock(&queue->lock);
		return 0;
	}
	event = &queue->events[queue->head];
	event->size = data_size;
	memcpy(event->data, data, data_size);
	queue->head = (queue->head + 1) % queue->capacity;
	queue->count++;
	pthread_cond_signal(&queue->not_empty);
	pthread_mutex_unlock(&queue->lock);
	return 0;
}

static int queue_event(void *context, void *data, size_t data_size)
{
	return enqueue_event(context, data, data_size, false);
}

/* Returns 1 when BPF LSM is listed, 0 when it is not, and -1 if unknown. */
static int bpf_lsm_enabled(void)
{
	char buffer[4096];
	char *saveptr = NULL;
	char *token;
	size_t length;
	FILE *file;

	file = fopen("/sys/kernel/security/lsm", "r");
	if (!file)
		return -1;

	length = fread(buffer, 1, sizeof(buffer) - 1, file);
	fclose(file);
	buffer[length] = '\0';

	for (token = strtok_r(buffer, ",\n", &saveptr); token;
	     token = strtok_r(NULL, ",\n", &saveptr)) {
		if (strcmp(token, "bpf") == 0)
			return 1;
	}

	return 0;
}

static int parse_u64(const char *text, uint64_t *value)
{
	char *end = NULL;
	unsigned long long parsed;

	if (!text || !text[0] || text[0] == '-')
		return -1;
	errno = 0;
	parsed = strtoull(text, &end, 0);
	if (errno || !end || *end != '\0')
		return -1;

	*value = parsed;
	return 0;
}

static int parse_identity(const char *text, uid_t *uid, gid_t *gid)
{
	char *copy = strdup(text);
	char *separator;
	uint64_t uid_value;
	uint64_t gid_value;
	int result = -1;

	if (!copy)
		return -1;
	separator = strchr(copy, ':');
	if (!separator || strchr(separator + 1, ':'))
		goto out;
	*separator = '\0';
	if (parse_u64(copy, &uid_value) ||
	    parse_u64(separator + 1, &gid_value) || !uid_value || !gid_value ||
	    uid_value > UINT32_MAX || gid_value > UINT32_MAX)
		goto out;
	*uid = (uid_t)uid_value;
	*gid = (gid_t)gid_value;
	result = 0;
out:
	free(copy);
	return result;
}

static int parse_network_protocol(const char *text, uint8_t *protocol)
{
	uint64_t value;

	if (strcasecmp(text, "tcp") == 0) {
		*protocol = IPPROTO_TCP;
		return 0;
	}
	if (strcasecmp(text, "udp") == 0) {
		*protocol = IPPROTO_UDP;
		return 0;
	}
	if (parse_u64(text, &value) || value > UINT8_MAX)
		return -1;
	*protocol = (uint8_t)value;
	return 0;
}

static int parse_network_events(const char *text, uint64_t *event_mask)
{
	char *copy = strdup(text);
	char *saveptr = NULL;
	char *name;
	uint64_t mask = 0;

	if (!copy)
		return -1;
	for (name = strtok_r(copy, ",", &saveptr); name;
	     name = strtok_r(NULL, ",", &saveptr)) {
		if (strcmp(name, "all") == 0)
			mask |= AGENT_NETWORK_EVENT_MASK_ALL;
		else if (strcmp(name, "none") == 0)
			mask = 0;
		else if (strcmp(name, "connect") == 0)
			mask |= AGENT_EVENT_BIT(AGENT_EVENT_NETWORK_CONNECT);
		else if (strcmp(name, "bind") == 0)
			mask |= AGENT_EVENT_BIT(AGENT_EVENT_NETWORK_BIND);
		else if (strcmp(name, "listen") == 0)
			mask |= AGENT_EVENT_BIT(AGENT_EVENT_NETWORK_LISTEN);
		else if (strcmp(name, "accept") == 0)
			mask |= AGENT_EVENT_BIT(AGENT_EVENT_NETWORK_ACCEPT);
		else if (strcmp(name, "udp") == 0)
			mask |= AGENT_EVENT_BIT(AGENT_EVENT_NETWORK_UDP_SEND);
		else if (strcmp(name, "tcp-state") == 0)
			mask |= AGENT_EVENT_BIT(AGENT_EVENT_NETWORK_TCP_STATE);
		else {
			free(copy);
			return -1;
		}
	}
	free(copy);
	*event_mask = mask;
	return 0;
}

enum option_id {
	OPTION_NETWORK_PORT = 1000,
	OPTION_NETWORK_PROTOCOL,
	OPTION_RINGBUF_BYTES,
	OPTION_CGROUP_PATH,
	OPTION_NO_CGROUP_HOOKS,
	OPTION_NETWORK_EVENTS,
	OPTION_NETWORK_RATE,
	OPTION_NETWORK_BURST,
	OPTION_FORMAT,
	OPTION_QUEUE_CAPACITY,
	OPTION_RATE_MAP_ENTRIES,
	OPTION_SELF_TEST,
	OPTION_RUN_AS,
	OPTION_RETAIN_PRIVILEGES,
	OPTION_ALLOW_SPECIAL_OUTPUT,
	OPTION_SYSCALLS_ENTER_ONLY,
};

static void usage(const char *program)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS]\n"
		"  --syscalls           Enable high-volume syscall enter/exit events\n"
		"  --syscalls-enter-only  Enable syscall enter events only\n"
		"  --no-file            Disable BPF LSM file sensors\n"
		"  --target-pid PID     Collect only this process TGID\n"
		"  --target-cgroup ID   Collect only this cgroup ID\n"
		"  --network-port PORT  Keep network events for this relevant port\n"
		"  --network-protocol P Keep network events for tcp, udp, or protocol ID\n"
		"  --network-events LIST Load connect,bind,listen,accept,udp,tcp-state\n"
		"  --network-rate N     Limit each cgroup/event type to N events/sec\n"
		"  --network-burst N    Token-bucket burst size (default: rate)\n"
			"  --ringbuf-bytes N    Set each Ring Buffer size (4 KiB to 64 MiB)\n"
		"  --cgroup-path PATH   Attach socket-address hooks at PATH\n"
		"  --no-cgroup-hooks    Use syscall tracepoints without cgroup enrichment\n"
		"  --format FORMAT      Output ndjson (default) or binary frames\n"
			"  --queue-capacity N   Bounded writer queue slots (8 to 65536)\n"
			"  --rate-map-entries N Rate-limit LRU capacity (max: 65536)\n"
			"  --run-as UID:GID     Drop root privileges after BPF setup (default: 65534:65534)\n"
			"  --retain-privileges  Keep root privileges after BPF setup\n"
			"  --allow-special-output  Permit trusted FIFO/character-device output\n"
		"  --self-test          Load, attach, poll briefly, then exit\n"
		"  --output PATH        Write NDJSON to PATH instead of stdout\n"
		"  --help               Show this help\n",
		program);
}

static int parse_options(int argc, char **argv, struct options *options)
{
	static const struct option long_options[] = {
		{ "syscalls", no_argument, NULL, 's' },
		{ "syscalls-enter-only", no_argument, NULL,
		  OPTION_SYSCALLS_ENTER_ONLY },
		{ "no-file", no_argument, NULL, 'F' },
		{ "target-pid", required_argument, NULL, 'p' },
		{ "target-cgroup", required_argument, NULL, 'c' },
		{ "network-port", required_argument, NULL, OPTION_NETWORK_PORT },
		{ "network-protocol", required_argument, NULL,
		  OPTION_NETWORK_PROTOCOL },
		{ "network-events", required_argument, NULL,
		  OPTION_NETWORK_EVENTS },
		{ "network-rate", required_argument, NULL, OPTION_NETWORK_RATE },
		{ "network-burst", required_argument, NULL, OPTION_NETWORK_BURST },
		{ "ringbuf-bytes", required_argument, NULL, OPTION_RINGBUF_BYTES },
		{ "cgroup-path", required_argument, NULL, OPTION_CGROUP_PATH },
		{ "no-cgroup-hooks", no_argument, NULL, OPTION_NO_CGROUP_HOOKS },
		{ "format", required_argument, NULL, OPTION_FORMAT },
		{ "queue-capacity", required_argument, NULL, OPTION_QUEUE_CAPACITY },
		{ "rate-map-entries", required_argument, NULL,
		  OPTION_RATE_MAP_ENTRIES },
			{ "self-test", no_argument, NULL, OPTION_SELF_TEST },
			{ "run-as", required_argument, NULL, OPTION_RUN_AS },
			{ "retain-privileges", no_argument, NULL,
			  OPTION_RETAIN_PRIVILEGES },
			{ "allow-special-output", no_argument, NULL,
			  OPTION_ALLOW_SPECIAL_OUTPUT },
		{ "output", required_argument, NULL, 'o' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	int option;

	while ((option = getopt_long(argc, argv, "sFp:c:o:h", long_options,
				     NULL)) != -1) {
		switch (option) {
		case 's':
			options->enable_syscalls = true;
			break;
		case OPTION_SYSCALLS_ENTER_ONLY:
			options->enable_syscalls = true;
			options->syscalls_enter_only = true;
			break;
		case 'F':
			options->enable_files = false;
			break;
		case 'p': {
			uint64_t pid;

			if (parse_u64(optarg, &pid) || pid > UINT32_MAX) {
				fprintf(stderr, "invalid target PID: %s\n", optarg);
				return -1;
			}
			options->target_tgid = (uint32_t)pid;
			break;
		}
		case 'c':
			if (parse_u64(optarg, &options->target_cgroup_id)) {
				fprintf(stderr, "invalid cgroup ID: %s\n", optarg);
				return -1;
			}
			break;
		case 'o':
			options->output_path = optarg;
			break;
		case OPTION_NETWORK_PORT: {
			uint64_t port;

			if (parse_u64(optarg, &port) || !port || port > UINT16_MAX) {
				fprintf(stderr, "invalid network port: %s\n", optarg);
				return -1;
			}
			options->network_port = (uint16_t)port;
			break;
		}
		case OPTION_NETWORK_PROTOCOL:
			if (parse_network_protocol(optarg,
						   &options->network_protocol)) {
				fprintf(stderr, "invalid network protocol: %s\n", optarg);
				return -1;
			}
			break;
		case OPTION_NETWORK_EVENTS:
			if (parse_network_events(optarg,
						 &options->network_event_mask)) {
				fprintf(stderr, "invalid network event list: %s\n", optarg);
				return -1;
			}
			break;
		case OPTION_NETWORK_RATE: {
			uint64_t rate;

			if (parse_u64(optarg, &rate) || !rate || rate > 1000000) {
				fprintf(stderr, "invalid network rate: %s\n", optarg);
				return -1;
			}
			options->network_rate = (uint32_t)rate;
			break;
		}
		case OPTION_NETWORK_BURST: {
			uint64_t burst;

			if (parse_u64(optarg, &burst) || !burst || burst > 1000000) {
				fprintf(stderr, "invalid network burst: %s\n", optarg);
				return -1;
			}
			options->network_burst = (uint32_t)burst;
			break;
		}
		case OPTION_RINGBUF_BYTES:
			if (parse_u64(optarg, &options->ring_buffer_bytes) ||
			    options->ring_buffer_bytes < 4096 ||
				    options->ring_buffer_bytes > MAX_RING_BUFFER_BYTES ||
			    (options->ring_buffer_bytes &
			     (options->ring_buffer_bytes - 1))) {
				fprintf(stderr,
						"ring-buffer size must be a power of two between 4096 and 67108864\n");
				return -1;
			}
			break;
		case OPTION_CGROUP_PATH:
			options->cgroup_path = optarg;
			break;
		case OPTION_NO_CGROUP_HOOKS:
			options->enable_cgroup_hooks = false;
			break;
		case OPTION_FORMAT:
			if (strcmp(optarg, "ndjson") == 0)
				options->format = OUTPUT_NDJSON;
			else if (strcmp(optarg, "binary") == 0)
				options->format = OUTPUT_BINARY;
			else {
				fprintf(stderr, "invalid output format: %s\n", optarg);
				return -1;
			}
			break;
		case OPTION_QUEUE_CAPACITY: {
			uint64_t capacity;

				if (parse_u64(optarg, &capacity) || capacity < 8 ||
				    capacity > MAX_QUEUE_CAPACITY) {
				fprintf(stderr, "invalid queue capacity: %s\n", optarg);
				return -1;
			}
			options->queue_capacity = (uint32_t)capacity;
			break;
		}
		case OPTION_RATE_MAP_ENTRIES: {
			uint64_t entries;

				if (parse_u64(optarg, &entries) || !entries ||
				    entries > MAX_RATE_MAP_ENTRIES) {
				fprintf(stderr, "invalid rate Map capacity: %s\n", optarg);
				return -1;
			}
			options->rate_map_entries = (uint32_t)entries;
			break;
		}
			case OPTION_SELF_TEST:
				options->self_test = true;
				break;
			case OPTION_RUN_AS:
				if (parse_identity(optarg, &options->run_uid,
						   &options->run_gid)) {
					fprintf(stderr, "invalid UID:GID: %s\n", optarg);
					return -1;
				}
				options->run_as_set = true;
				break;
			case OPTION_RETAIN_PRIVILEGES:
				options->retain_privileges = true;
				break;
			case OPTION_ALLOW_SPECIAL_OUTPUT:
				options->allow_special_output = true;
				break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
		default:
			usage(argv[0]);
			return -1;
		}
		}
	if (optind != argc) {
		fprintf(stderr, "unexpected positional argument: %s\n", argv[optind]);
		return -1;
	}

	return 0;
}

static void print_stats(const struct reader_state *state, int lost_map_fd)
{
	int cpu_count;
	uint64_t *per_cpu;
	uint32_t type;

	cpu_count = libbpf_num_possible_cpus();
	if (cpu_count <= 0)
		return;

	per_cpu = calloc(cpu_count, sizeof(*per_cpu));
	if (!per_cpu)
		return;

	fputs("event statistics:\n", stderr);
	for (type = 1; type < AGENT_EVENT_TYPE_MAX; type++) {
		uint64_t lost = 0;
		int cpu;

		memset(per_cpu, 0, cpu_count * sizeof(*per_cpu));
		if (bpf_map_lookup_elem(lost_map_fd, &type, per_cpu) == 0) {
			for (cpu = 0; cpu < cpu_count; cpu++)
				lost += per_cpu[cpu];
		}

		fprintf(stderr, "  %-16s received=%" PRIu64 " lost=%" PRIu64 "\n",
			event_type_name(type), state->received[type], lost);
	}

	free(per_cpu);
}

static void print_network_stats(int stats_map_fd)
{
	static const char *const names[] = {
		"map_update_failed",
		"socket_read_failed",
		"ringbuf_lost",
		"user_read_failed",
		"filtered",
		"rate_limited",
	};
	int cpu_count;
	uint64_t *per_cpu;
	uint32_t index;

	cpu_count = libbpf_num_possible_cpus();
	if (cpu_count <= 0)
		return;
	per_cpu = calloc(cpu_count, sizeof(*per_cpu));
	if (!per_cpu)
		return;

	fputs("network sensor statistics:\n", stderr);
	for (index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
		uint64_t total = 0;
		int cpu;

		memset(per_cpu, 0, cpu_count * sizeof(*per_cpu));
		if (bpf_map_lookup_elem(stats_map_fd, &index, per_cpu) == 0) {
			for (cpu = 0; cpu < cpu_count; cpu++)
				total += per_cpu[cpu];
		}
		fprintf(stderr, "  %-20s %" PRIu64 "\n", names[index], total);
	}

	free(per_cpu);
}

static uint64_t read_percpu_total(int map_fd, uint32_t key)
{
	int cpu_count = libbpf_num_possible_cpus();
	uint64_t *per_cpu;
	uint64_t total = 0;
	int cpu;

	if (cpu_count <= 0)
		return 0;
	per_cpu = calloc((size_t)cpu_count, sizeof(*per_cpu));
	if (!per_cpu)
		return 0;
	if (bpf_map_lookup_elem(map_fd, &key, per_cpu) == 0) {
		for (cpu = 0; cpu < cpu_count; cpu++)
			total += per_cpu[cpu];
	}
	free(per_cpu);
	return total;
}

static uint64_t read_host_ringbuf_lost(int map_fd)
{
	uint64_t total = 0;
	uint32_t type;

	for (type = 1; type < AGENT_EVENT_TYPE_MAX; type++)
		total += read_percpu_total(map_fd, type);
	return total;
}

static void prepare_health_event(struct agent_event *event,
				 struct reader_state *state, int lost_map_fd,
				 int network_stats_fd)
{
	uint32_t process_id = (uint32_t)getpid();

	memset(event, 0, sizeof(*event));
	event->header.timestamp_ns = monotonic_ns();
	event->header.pid = process_id;
	event->header.tgid = process_id;
	event->header.namespace_pid = process_id;
	event->header.namespace_tgid = process_id;
	event->header.ppid = (uint32_t)getppid();
	event->header.uid = (uint32_t)getuid();
	event->header.gid = (uint32_t)getgid();
	event->header.size = AGENT_HEALTH_EVENT_SIZE;
	event->header.flags = AGENT_FLAG_USERSPACE_GENERATED;
	event->header.version = AGENT_SCHEMA_VERSION;
	event->header.type = AGENT_EVENT_HEALTH;
	memcpy(event->header.comm, "ebpf-agent", sizeof("ebpf-agent"));
	event->data.health.writer_queue_dropped = atomic_load_explicit(
		&state->queue->dropped, memory_order_relaxed);
	event->data.health.writer_priority_dropped = atomic_load_explicit(
		&state->queue->priority_dropped, memory_order_relaxed);
	event->data.health.kernel_ringbuf_lost =
		read_host_ringbuf_lost(lost_map_fd) +
		read_percpu_total(network_stats_fd,
				   NETWORK_STAT_RINGBUF_LOST_INDEX);
	event->data.health.network_filtered = read_percpu_total(
		network_stats_fd, NETWORK_STAT_FILTERED_INDEX);
	event->data.health.network_rate_limited = read_percpu_total(
		network_stats_fd, NETWORK_STAT_RATE_LIMITED_INDEX);
}

static int enqueue_health_event(struct reader_state *state, int lost_map_fd,
				int network_stats_fd)
{
	struct agent_event event;

	prepare_health_event(&event, state, lost_map_fd, network_stats_fd);
	return enqueue_event(state, &event, event.header.size, true);
}

static int write_health_event(struct reader_state *state, int lost_map_fd,
			      int network_stats_fd)
{
	struct agent_event event;

	prepare_health_event(&event, state, lost_map_fd, network_stats_fd);
	return write_event(state, &event, event.header.size);
}

int main(int argc, char **argv)
{
	struct options options = {
		.enable_files = true,
		.enable_cgroup_hooks = true,
		.cgroup_path = "/sys/fs/cgroup",
		.network_event_mask = AGENT_NETWORK_EVENT_MASK_DEFAULT,
		.queue_capacity = 4096,
		.run_uid = 65534,
		.run_gid = 65534,
	};
	struct reader_state state = { .output = stdout };
	struct event_queue event_queue = {};
	struct agent_config configuration = {};
	struct host_events_bpf *skeleton = NULL;
	struct server_bpf *network_skeleton = NULL;
	struct ring_buffer *ring = NULL;
	struct bpf_link *cgroup_links[NETWORK_CGROUP_PROGRAM_COUNT] = {};
	int cgroup_fd = -1;
	int lsm_state;
	int error = 0;
	int self_test_polls = 0;
	uint64_t last_health_ns = 0;
	uint32_t key = 0;
	struct stat pid_namespace = {};

	if (parse_options(argc, argv, &options))
		return EXIT_FAILURE;
	state.format = options.format;
	state.queue = &event_queue;
	if (options.enable_syscalls && !options.target_tgid &&
	    !options.target_cgroup_id) {
		fprintf(stderr,
			"--syscalls requires --target-pid or --target-cgroup to prevent an event storm\n");
		return EXIT_FAILURE;
	}
	if (options.network_burst && !options.network_rate) {
		fprintf(stderr, "--network-burst requires --network-rate\n");
		return EXIT_FAILURE;
	}
	if (options.network_rate && !options.network_burst)
		options.network_burst = options.network_rate;
	if (options.retain_privileges && options.run_as_set) {
		fprintf(stderr, "--run-as and --retain-privileges are mutually exclusive\n");
		return EXIT_FAILURE;
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	if (bump_memlock_limit() && errno != EPERM)
		fprintf(stderr, "warning: unable to raise memlock limit: %s\n",
			strerror(errno));

	skeleton = host_events_bpf__open();
	if (!skeleton) {
		fprintf(stderr, "failed to open eBPF skeleton\n");
		error = -ENOMEM;
		goto cleanup;
	}
	network_skeleton = server_bpf__open();
	if (!network_skeleton) {
		fprintf(stderr, "failed to open network eBPF skeleton\n");
		error = -ENOMEM;
		goto cleanup;
	}
	bpf_program__set_autoattach(network_skeleton->progs.enrich_connect4,
				    false);
	bpf_program__set_autoattach(network_skeleton->progs.enrich_connect6,
				    false);
	bpf_program__set_autoattach(network_skeleton->progs.enrich_bind4, false);
	bpf_program__set_autoattach(network_skeleton->progs.enrich_bind6, false);
	bpf_program__set_autoattach(network_skeleton->progs.enrich_sendmsg4,
				    false);
	bpf_program__set_autoattach(network_skeleton->progs.enrich_sendmsg6,
				    false);
	bpf_program__set_autoattach(network_skeleton->progs.observe_tcp_states,
				    false);
	if (!(options.network_event_mask &
	      AGENT_EVENT_BIT(AGENT_EVENT_NETWORK_CONNECT))) {
		bpf_program__set_autoload(network_skeleton->progs.trace_connect_enter,
					 false);
		bpf_program__set_autoload(network_skeleton->progs.trace_connect_exit,
					 false);
		bpf_program__set_autoload(network_skeleton->progs.enrich_connect4,
					 false);
		bpf_program__set_autoload(network_skeleton->progs.enrich_connect6,
					 false);
	}
	if (!(options.network_event_mask &
	      AGENT_EVENT_BIT(AGENT_EVENT_NETWORK_BIND))) {
		bpf_program__set_autoload(network_skeleton->progs.trace_bind_enter,
					 false);
		bpf_program__set_autoload(network_skeleton->progs.trace_bind_exit,
					 false);
		bpf_program__set_autoload(network_skeleton->progs.enrich_bind4, false);
		bpf_program__set_autoload(network_skeleton->progs.enrich_bind6, false);
	}
	if (!(options.network_event_mask &
	      AGENT_EVENT_BIT(AGENT_EVENT_NETWORK_LISTEN))) {
		bpf_program__set_autoload(network_skeleton->progs.trace_listen_enter,
					 false);
		bpf_program__set_autoload(network_skeleton->progs.trace_listen_exit,
					 false);
	}
	if (!(options.network_event_mask &
	      AGENT_EVENT_BIT(AGENT_EVENT_NETWORK_ACCEPT))) {
		bpf_program__set_autoload(network_skeleton->progs.trace_accept_enter,
					 false);
		bpf_program__set_autoload(network_skeleton->progs.trace_accept_exit,
					 false);
		bpf_program__set_autoload(network_skeleton->progs.trace_accept4_enter,
					 false);
		bpf_program__set_autoload(network_skeleton->progs.trace_accept4_exit,
					 false);
	}
	if (!(options.network_event_mask &
	      AGENT_EVENT_BIT(AGENT_EVENT_NETWORK_UDP_SEND))) {
		bpf_program__set_autoload(network_skeleton->progs.trace_sendto_enter,
					 false);
		bpf_program__set_autoload(network_skeleton->progs.trace_sendto_exit,
					 false);
		bpf_program__set_autoload(network_skeleton->progs.trace_sendmsg_enter,
					 false);
		bpf_program__set_autoload(network_skeleton->progs.trace_sendmsg_exit,
					 false);
		bpf_program__set_autoload(network_skeleton->progs.enrich_sendmsg4,
					 false);
		bpf_program__set_autoload(network_skeleton->progs.enrich_sendmsg6,
					 false);
	}
	if (!(options.network_event_mask &
	      AGENT_EVENT_BIT(AGENT_EVENT_NETWORK_TCP_STATE))) {
		bpf_program__set_autoload(network_skeleton->progs.trace_tcp_state,
					 false);
		bpf_program__set_autoload(network_skeleton->progs.observe_tcp_states,
					 false);
	}
	if (!options.enable_cgroup_hooks) {
		bpf_program__set_autoload(network_skeleton->progs.enrich_connect4,
					 false);
		bpf_program__set_autoload(network_skeleton->progs.enrich_connect6,
					 false);
		bpf_program__set_autoload(network_skeleton->progs.enrich_bind4,
					 false);
		bpf_program__set_autoload(network_skeleton->progs.enrich_bind6,
					 false);
		bpf_program__set_autoload(network_skeleton->progs.enrich_sendmsg4,
					 false);
		bpf_program__set_autoload(network_skeleton->progs.enrich_sendmsg6,
					 false);
		bpf_program__set_autoload(network_skeleton->progs.observe_tcp_states,
					 false);
	}

	if (options.ring_buffer_bytes) {
		if (bpf_map__set_max_entries(skeleton->maps.events,
					     options.ring_buffer_bytes) ||
		    bpf_map__set_max_entries(network_skeleton->maps.network_events,
					     options.ring_buffer_bytes)) {
			fprintf(stderr, "failed to configure Ring Buffer size\n");
			error = -EINVAL;
			goto cleanup;
		}
	}
	if (options.rate_map_entries &&
	    bpf_map__set_max_entries(network_skeleton->maps.network_rate_limits,
				     options.rate_map_entries)) {
		fprintf(stderr, "failed to configure rate-limit Map capacity\n");
		error = -EINVAL;
		goto cleanup;
	}

	if (!options.enable_syscalls) {
		bpf_program__set_autoload(skeleton->progs.handle_syscall_enter, false);
		bpf_program__set_autoload(skeleton->progs.handle_syscall_exit, false);
	}

	if (!options.enable_files) {
		bpf_program__set_autoload(skeleton->progs.handle_file_open, false);
		bpf_program__set_autoload(skeleton->progs.handle_file_unlink, false);
	} else {
		lsm_state = bpf_lsm_enabled();
		if (lsm_state == 0) {
			bpf_program__set_autoload(skeleton->progs.handle_file_open,
						 false);
			bpf_program__set_autoload(skeleton->progs.handle_file_unlink,
						 false);
			options.enable_files = false;
			fprintf(stderr, "warning: BPF LSM is disabled; file sensors skipped\n");
		} else if (lsm_state < 0) {
			fprintf(stderr,
				"warning: unable to inspect active LSMs; use --no-file if load fails\n");
		}
	}

	error = host_events_bpf__load(skeleton);
	if (error) {
		fprintf(stderr, "failed to load eBPF programs: %d\n", error);
		goto cleanup;
	}
	error = server_bpf__load(network_skeleton);
	if (error) {
		fprintf(stderr, "failed to load network eBPF programs: %d\n", error);
		goto cleanup;
	}

	configuration.event_mask =
		AGENT_EVENT_BIT(AGENT_EVENT_PROCESS_FORK) |
		AGENT_EVENT_BIT(AGENT_EVENT_PROCESS_EXEC) |
		AGENT_EVENT_BIT(AGENT_EVENT_PROCESS_EXIT) |
		options.network_event_mask;
	if (options.enable_syscalls) {
		configuration.event_mask |=
			AGENT_EVENT_BIT(AGENT_EVENT_SYSCALL_ENTER);
		if (!options.syscalls_enter_only)
			configuration.event_mask |=
				AGENT_EVENT_BIT(AGENT_EVENT_SYSCALL_EXIT);
	}
	if (options.enable_files)
		configuration.event_mask |=
			AGENT_EVENT_BIT(AGENT_EVENT_FILE_OPEN) |
			AGENT_EVENT_BIT(AGENT_EVENT_FILE_UNLINK);
	configuration.target_tgid = options.target_tgid;
	configuration.target_cgroup_id = options.target_cgroup_id;
	configuration.exclude_tgid = getpid();
	configuration.network_destination_port = options.network_port;
	configuration.network_protocol = options.network_protocol;
	if (options.network_rate) {
		configuration.network_rate_interval_ns =
			1000000000ULL / options.network_rate;
		if (!configuration.network_rate_interval_ns)
			configuration.network_rate_interval_ns = 1;
		configuration.network_rate_burst_ns =
			configuration.network_rate_interval_ns *
			(options.network_burst - 1ULL);
	}
	if (stat("/proc/self/ns/pid", &pid_namespace) == 0) {
		configuration.pidns_device = pid_namespace.st_dev;
		configuration.pidns_inode = pid_namespace.st_ino;
	} else {
		fprintf(stderr,
			"warning: unable to identify PID namespace; PID filters use host IDs\n");
	}

	if (bpf_map_update_elem(bpf_map__fd(skeleton->maps.agent_config_map), &key,
				&configuration, BPF_ANY)) {
		error = -errno;
		fprintf(stderr, "failed to configure sensors: %s\n", strerror(errno));
		goto cleanup;
	}
	if (bpf_map_update_elem(
		bpf_map__fd(network_skeleton->maps.network_config_map), &key,
		&configuration, BPF_ANY)) {
		error = -errno;
		fprintf(stderr, "failed to configure network sensor: %s\n",
			strerror(errno));
		goto cleanup;
	}

	error = host_events_bpf__attach(skeleton);
	if (error) {
		fprintf(stderr, "failed to attach eBPF programs: %d\n", error);
		goto cleanup;
	}
	error = server_bpf__attach(network_skeleton);
	if (error) {
		fprintf(stderr, "failed to attach network eBPF programs: %d\n", error);
		goto cleanup;
	}

	if (options.enable_cgroup_hooks) {
		struct bpf_program *programs[NETWORK_CGROUP_PROGRAM_COUNT] = {
			network_skeleton->progs.enrich_connect4,
			network_skeleton->progs.enrich_connect6,
			network_skeleton->progs.enrich_bind4,
			network_skeleton->progs.enrich_bind6,
			network_skeleton->progs.enrich_sendmsg4,
			network_skeleton->progs.enrich_sendmsg6,
			network_skeleton->progs.observe_tcp_states,
		};
		const char *names[NETWORK_CGROUP_PROGRAM_COUNT] = {
			"connect4", "connect6", "bind4", "bind6",
			"sendmsg4", "sendmsg6", "sockops",
		};
		int index;

		cgroup_fd = open(options.cgroup_path,
				 O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (cgroup_fd < 0) {
			fprintf(stderr,
				"warning: unable to open cgroup path %s: %s; using tracepoint fallback\n",
				options.cgroup_path, strerror(errno));
		} else {
			for (index = 0; index < NETWORK_CGROUP_PROGRAM_COUNT;
			     index++) {
				long attach_error;

				if (!bpf_program__autoload(programs[index]))
					continue;
				cgroup_links[index] = bpf_program__attach_cgroup(
					programs[index], cgroup_fd);
				attach_error = libbpf_get_error(cgroup_links[index]);
				if (attach_error) {
					cgroup_links[index] = NULL;
					fprintf(stderr,
						"warning: cgroup/%s attach failed: %ld\n",
						names[index], attach_error);
				}
			}
			if (cgroup_links[6]) {
				configuration.network_flags |=
					AGENT_NETWORK_CONFIG_SOCKOPS_STATE;
				if (bpf_map_update_elem(
					bpf_map__fd(network_skeleton->maps.network_config_map),
					&key, &configuration, BPF_ANY)) {
					error = -errno;
					fprintf(stderr,
						"failed to enable sockops state tracking: %s\n",
						strerror(errno));
					goto cleanup;
				}
			}
		}
	}

	ring = ring_buffer__new(bpf_map__fd(skeleton->maps.events), queue_event,
				&state, NULL);
	if (!ring) {
		error = -errno;
		fprintf(stderr, "failed to create ring-buffer reader: %s\n",
			strerror(errno));
		goto cleanup;
	}
	error = ring_buffer__add(
		ring, bpf_map__fd(network_skeleton->maps.network_events),
		queue_event, &state);
	if (error) {
		fprintf(stderr, "failed to add network ring buffer: %d\n", error);
		goto cleanup;
	}

	if (options.output_path) {
		error = secure_open_output(options.output_path, options.format,
					   options.allow_special_output,
					   &state.output);
		if (error) {
			fprintf(stderr, "failed to securely open %s: %s\n",
				options.output_path, strerror(-error));
			goto cleanup;
		}
		setvbuf(state.output, NULL, _IOFBF, 1024 * 1024);
	}
	if (!options.retain_privileges) {
		error = drop_root_privileges(options.run_uid, options.run_gid);
		if (error) {
			fprintf(stderr, "failed to drop privileges: %s\n",
				strerror(-error));
			goto cleanup;
		}
	}
	error = event_queue_start(&event_queue, &state, options.queue_capacity);
	if (error) {
		fprintf(stderr, "failed to start writer queue: %s\n",
			strerror(-error));
		goto cleanup;
	}
	state.last_flush_ns = monotonic_ns();
	last_health_ns = state.last_flush_ns;

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	signal(SIGPIPE, SIG_IGN);
	fprintf(stderr,
		"host event sensors started (syscalls=%s files=%s target_pid=%u)\n",
		options.enable_syscalls ? "on" : "off",
		options.enable_files ? "on" : "off", options.target_tgid);

	while (!stop) {
		uint64_t now;

		error = ring_buffer__poll(ring, options.self_test ? 100 : 250);
		if (error == -EINTR) {
			error = 0;
			break;
		}
		if (error < 0) {
			fprintf(stderr, "ring-buffer poll failed: %d\n", error);
			break;
		}
		if (state.output_error) {
			error = state.output_error;
			fprintf(stderr, "output write failed: %s\n",
				strerror(-state.output_error));
			break;
		}
		now = monotonic_ns();
		if (now - last_health_ns >= HEALTH_INTERVAL_NS) {
			enqueue_health_event(
				&state, bpf_map__fd(skeleton->maps.lost_events),
				bpf_map__fd(network_skeleton->maps.network_stats));
			last_health_ns = now;
		}
		if (options.self_test && ++self_test_polls >= 5)
			break;
	}

	event_queue_finish(&event_queue);
	if (!state.output_error)
		write_health_event(&state,
				   bpf_map__fd(skeleton->maps.lost_events),
				   bpf_map__fd(network_skeleton->maps.network_stats));
	flush_output(&state, true);
	fprintf(stderr, "writer queue dropped=%" PRIu64 "\n",
		(uint64_t)atomic_load_explicit(&event_queue.dropped,
					       memory_order_relaxed));
	fprintf(stderr, "writer priority dropped=%" PRIu64 "\n",
		(uint64_t)atomic_load_explicit(&event_queue.priority_dropped,
					       memory_order_relaxed));
	print_stats(&state, bpf_map__fd(skeleton->maps.lost_events));
	print_network_stats(bpf_map__fd(network_skeleton->maps.network_stats));

cleanup:
	event_queue_finish(&event_queue);
	flush_output(&state, true);
	if (!error && state.output_error)
		error = state.output_error;
	ring_buffer__free(ring);
	for (int index = 0; index < NETWORK_CGROUP_PROGRAM_COUNT; index++)
		bpf_link__destroy(cgroup_links[index]);
	if (cgroup_fd >= 0)
		close(cgroup_fd);
	server_bpf__destroy(network_skeleton);
	host_events_bpf__destroy(skeleton);
	if (state.output && state.output != stdout)
		fclose(state.output);
	return error < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
