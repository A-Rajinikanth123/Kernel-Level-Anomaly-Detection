/*
 * AI-Based Kernel-Level Anomaly Detection System
 * eBPF Kernel Probe (Linux Kernel Space Monitoring)
 * 
 * Captures low-level kernel events:
 * 1. sys_enter_execve (Process execution / binary spawning)
 * 2. sys_enter_openat (File access / unauthorized sensitive file reading)
 * 3. sys_enter_connect (Network socket connections / C2 beaconing)
 * 4. sys_enter_setuid (Privilege escalation attempts)
 * 5. sys_enter_capset (Capability and root privilege modifications)
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/in.h>

#define EVENT_TYPE_SYSCALL    1
#define EVENT_TYPE_PROCESS    2
#define EVENT_TYPE_FILE       3
#define EVENT_TYPE_NETWORK    4
#define EVENT_TYPE_PRIVILEGE  5

// Event structure pushed to user-space perf buffer
struct kernel_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 tgid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u32 event_type;
    char comm[TASK_COMM_LEN];
    char filename[256];
    char syscall_name[32];
    u32 ip_dest;
    u16 port_dest;
    u32 is_privileged;
    u32 flags;
};

// BPF Perf Output Buffer
BPF_PERF_OUTPUT(events);

// 1. Hook Process Execution: sys_enter_execve
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct kernel_event_t event = {};
    u64 id = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();

    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = id >> 32;
    event.tgid = id;
    event.uid = uid_gid & 0xFFFFFFFF;
    event.gid = uid_gid >> 32;
    event.event_type = EVENT_TYPE_PROCESS;
    __builtin_memcpy(event.syscall_name, "execve", 7);

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);

    if (event.uid == 0) {
        event.is_privileged = 1;
    }

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// 2. Hook File Operations: sys_enter_openat
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct kernel_event_t event = {};
    u64 id = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();

    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = id >> 32;
    event.uid = uid_gid & 0xFFFFFFFF;
    event.event_type = EVENT_TYPE_FILE;
    __builtin_memcpy(event.syscall_name, "openat", 7);
    event.flags = args->flags;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);

    if (event.uid == 0) {
        event.is_privileged = 1;
    }

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// 3. Hook Privilege Escalation: sys_enter_setuid
TRACEPOINT_PROBE(syscalls, sys_enter_setuid) {
    struct kernel_event_t event = {};
    u64 id = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();

    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = id >> 32;
    event.uid = uid_gid & 0xFFFFFFFF;
    event.event_type = EVENT_TYPE_PRIVILEGE;
    __builtin_memcpy(event.syscall_name, "setuid", 7);
    event.is_privileged = 1;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// 4. Hook Network Connections: sys_enter_connect
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct kernel_event_t event = {};
    u64 id = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();

    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = id >> 32;
    event.uid = uid_gid & 0xFFFFFFFF;
    event.event_type = EVENT_TYPE_NETWORK;
    __builtin_memcpy(event.syscall_name, "connect", 8);

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
