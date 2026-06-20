#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_COMM_LEN 64
#define MAX_SUN_PATH 108
#define AF_INET 2
#define AF_INET6 10
#define AF_UNIX 1

#define EVENT_TYPE_INET_CONNECT 1
#define EVENT_TYPE_INET_ACCEPT  2
#define EVENT_TYPE_UNIX_CONNECT 3
#define EVENT_TYPE_UNIX_ACCEPT  4
#define EVENT_TYPE_CLOSE        5

struct event_header {
    u32 event_type;
    u32 pid;
    u32 tid;
    char comm[MAX_COMM_LEN];
};

struct inet_connect_event {
    struct event_header hdr;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 padding;
};

struct inet_accept_event {
    struct event_header hdr;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 padding;
};

struct unix_connect_event {
    struct event_header hdr;
    char sun_path[MAX_SUN_PATH];
    u32 padding;
};

struct unix_accept_event {
    struct event_header hdr;
    char sun_path[MAX_SUN_PATH];
    u32 padding;
};

struct close_event {
    struct event_header hdr;
    u64 fd;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct active_connect_info {
    struct event_header hdr;
    u32 addr_type;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char sun_path[MAX_SUN_PATH];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);
    __type(value, struct active_connect_info);
} active_connects SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);
    __type(value, struct event_header);
} active_accepts SEC(".maps");

static __always_inline int parse_inet_sockaddr(struct sockaddr *addr, u32 *ip, u16 *port)
{
    sa_family_t family;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);

    if (family == AF_INET) {
        struct sockaddr_in sin;
        bpf_probe_read_user(&sin, sizeof(sin), addr);
        *ip = sin.sin_addr.s_addr;
        *port = __builtin_bswap16(sin.sin_port);
        return AF_INET;
    }
    return 0;
}

static __always_inline int parse_unix_sockaddr(struct sockaddr *addr, char *out_path, int max_len)
{
    sa_family_t family;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);

    if (family == AF_UNIX) {
        struct sockaddr_un *sun = (struct sockaddr_un *)addr;
        bpf_probe_read_user(out_path, max_len, &sun->sun_path);
        return AF_UNIX;
    }
    return 0;
}

static __always_inline void fill_header(struct event_header *hdr, u32 type, u64 id)
{
    hdr->event_type = type;
    hdr->pid = id >> 32;
    hdr->tid = (u32)id;
    bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));
}

SEC("kprobe/__sys_connect")
int trace_connect_entry(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct active_connect_info info = {};

    fill_header(&info.hdr, 0, id);

    struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2(ctx);

    u32 ip = 0;
    u16 port = 0;
    int family = parse_inet_sockaddr(addr, &ip, &port);
    if (family == AF_INET) {
        info.addr_type = AF_INET;
        info.daddr = ip;
        info.dport = port;
    } else {
        family = parse_unix_sockaddr(addr, info.sun_path, MAX_SUN_PATH);
        if (family == AF_UNIX) {
            info.addr_type = AF_UNIX;
        } else {
            return 0;
        }
    }

    bpf_map_update_elem(&active_connects, &id, &info, BPF_ANY);
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

    struct active_connect_info *info = bpf_map_lookup_elem(&active_connects, &id);
    if (!info)
        return 0;

    if (info->addr_type == AF_INET) {
        struct inet_connect_event *event = bpf_ringbuf_reserve(&events, sizeof(struct inet_connect_event), 0);
        if (!event) {
            bpf_map_delete_elem(&active_connects, &id);
            return 0;
        }
        fill_header(&event->hdr, EVENT_TYPE_INET_CONNECT, id);
        __builtin_memcpy(&event->hdr.comm, &info->hdr.comm, sizeof(event->hdr.comm));
        event->saddr = info->saddr;
        event->daddr = info->daddr;
        event->sport = info->sport;
        event->dport = info->dport;
        bpf_ringbuf_submit(event, 0);
    } else if (info->addr_type == AF_UNIX) {
        struct unix_connect_event *event = bpf_ringbuf_reserve(&events, sizeof(struct unix_connect_event), 0);
        if (!event) {
            bpf_map_delete_elem(&active_connects, &id);
            return 0;
        }
        fill_header(&event->hdr, EVENT_TYPE_UNIX_CONNECT, id);
        __builtin_memcpy(&event->hdr.comm, &info->hdr.comm, sizeof(event->hdr.comm));
        __builtin_memcpy(event->sun_path, info->sun_path, MAX_SUN_PATH);
        bpf_ringbuf_submit(event, 0);
    }

    bpf_map_delete_elem(&active_connects, &id);
    return 0;
}

SEC("kprobe/__sys_accept4")
int trace_accept_entry(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct event_header hdr = {};
    fill_header(&hdr, 0, id);
    bpf_map_update_elem(&active_accepts, &id, &hdr, BPF_ANY);
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

    struct event_header *stored = bpf_map_lookup_elem(&active_accepts, &id);
    if (!stored)
        return 0;

    struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2(ctx);

    u32 ip = 0;
    u16 port = 0;
    int family = parse_inet_sockaddr(addr, &ip, &port);

    if (family == AF_INET) {
        struct inet_accept_event *event = bpf_ringbuf_reserve(&events, sizeof(struct inet_accept_event), 0);
        if (!event) {
            bpf_map_delete_elem(&active_accepts, &id);
            return 0;
        }
        fill_header(&event->hdr, EVENT_TYPE_INET_ACCEPT, id);
        __builtin_memcpy(&event->hdr.comm, &stored->comm, sizeof(event->hdr.comm));
        event->saddr = ip;
        event->sport = port;
        bpf_ringbuf_submit(event, 0);
    } else {
        char path[MAX_SUN_PATH] = {};
        family = parse_unix_sockaddr(addr, path, MAX_SUN_PATH);
        if (family == AF_UNIX) {
            struct unix_accept_event *event = bpf_ringbuf_reserve(&events, sizeof(struct unix_accept_event), 0);
            if (!event) {
                bpf_map_delete_elem(&active_accepts, &id);
                return 0;
            }
            fill_header(&event->hdr, EVENT_TYPE_UNIX_ACCEPT, id);
            __builtin_memcpy(&event->hdr.comm, &stored->comm, sizeof(event->hdr.comm));
            __builtin_memcpy(event->sun_path, path, MAX_SUN_PATH);
            bpf_ringbuf_submit(event, 0);
        }
    }

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

    fill_header(&event->hdr, EVENT_TYPE_CLOSE, id);
    event->fd = (u64)PT_REGS_PARM1(ctx);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
