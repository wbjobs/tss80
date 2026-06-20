#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_COMM_LEN 64
#define MAX_ARGS_LEN 256
#define AF_INET 2
#define AF_INET6 10

struct connect_event {
    u32 pid;
    u32 tid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char comm[MAX_COMM_LEN];
};

struct accept_event {
    u32 pid;
    u32 tid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char comm[MAX_COMM_LEN];
};

struct close_event {
    u32 pid;
    u32 tid;
    u64 fd;
    char comm[MAX_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);
    __type(value, struct connect_event);
} active_connects SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);
    __type(value, struct accept_event);
} active_accepts SEC(".maps");

static __always_inline int parse_sockaddr(struct sockaddr *addr, u32 *ip, u16 *port)
{
    sa_family_t family;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);

    if (family == AF_INET) {
        struct sockaddr_in sin;
        bpf_probe_read_user(&sin, sizeof(sin), addr);
        *ip = sin.sin_addr.s_addr;
        *port = __builtin_bswap16(sin.sin_port);
        return 0;
    }
    return -1;
}

SEC("kprobe/__sys_connect")
int trace_connect_entry(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct connect_event *event = bpf_ringbuf_reserve(&events, sizeof(struct connect_event), 0);
    if (!event)
        return 0;

    event->pid = id >> 32;
    event->tid = (u32)id;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    u32 ip = 0;
    u16 port = 0;
    if (parse_sockaddr(addr, &ip, &port) == 0) {
        event->daddr = ip;
        event->dport = port;
    }

    bpf_map_update_elem(&active_connects, &id, event, BPF_ANY);
    bpf_ringbuf_discard(event, 0);
    return 0;
}

SEC("kretprobe/__sys_connect")
int trace_connect_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    int ret = (int)PT_REGS_RC(ctx);

    if (ret < 0) {
        bpf_map_delete_elem(&active_connects, &id);
        return 0;
    }

    struct connect_event *stored = bpf_map_lookup_elem(&active_connects, &id);
    if (!stored)
        return 0;

    struct connect_event *event = bpf_ringbuf_reserve(&events, sizeof(struct connect_event), 0);
    if (!event) {
        bpf_map_delete_elem(&active_connects, &id);
        return 0;
    }

    __builtin_memcpy(event, stored, sizeof(struct connect_event));
    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&active_connects, &id);
    return 0;
}

SEC("kprobe/__sys_accept4")
int trace_accept_entry(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct accept_event event = {};
    event.pid = id >> 32;
    event.tid = (u32)id;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_map_update_elem(&active_accepts, &id, &event, BPF_ANY);
    return 0;
}

SEC("kretprobe/__sys_accept4")
int trace_accept_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    int ret = (int)PT_REGS_RC(ctx);

    if (ret < 0) {
        bpf_map_delete_elem(&active_accepts, &id);
        return 0;
    }

    struct accept_event *stored = bpf_map_lookup_elem(&active_accepts, &id);
    if (!stored)
        return 0;

    struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    struct accept_event *event = bpf_ringbuf_reserve(&events, sizeof(struct accept_event), 0);
    if (!event) {
        bpf_map_delete_elem(&active_accepts, &id);
        return 0;
    }

    __builtin_memcpy(event, stored, sizeof(struct accept_event));

    u32 ip = 0;
    u16 port = 0;
    if (parse_sockaddr(addr, &ip, &port) == 0) {
        event->saddr = ip;
        event->sport = port;
    }

    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&active_accepts, &id);
    return 0;
}

SEC("kprobe/__sys_close")
int trace_close(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct close_event *event = bpf_ringbuf_reserve(&events, sizeof(struct close_event), 0);
    if (!event)
        return 0;

    event->pid = id >> 32;
    event->tid = (u32)id;
    event->fd = (u64)PT_REGS_PARM1(ctx);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
