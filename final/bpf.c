#include <uapi/linux/ptrace.h>
#include <linux/socket.h>

#define PID 443626

// https://github.com/openbsd/src/blob/master/sys/sys/_types.h#L61
// https://github.com/pixie-io/pixie/blob/main/src/stirling/source_connectors/socket_tracer/bcc_bpf/socket_trace.c

// TODO: replace with the proper header
// typedef unsigned int socklen_t;
#define socklen_t size_t

struct accept_sys_args {
    struct sockaddr* addr;
};

struct accept_return {
    u64 time;
    char request[1024];
    unsigned int size;
};

BPF_HASH(addr_in_s, u32, struct accept_sys_args);
BPF_PERF_OUTPUT(events);
BPF_ARRAY(returns, struct accept_return, 1);


// https://man7.org/linux/man-pages/man2/accept.2.html
void syscall__accept4(
    struct pt_regs *ctx,
    int sockfd,
    // https://github.com/torvalds/linux/blob/master/include/linux/socket.h#L34
    struct sockaddr* addr,
    socklen_t* addrlen
    ) {
        u32 id = bpf_get_current_pid_tgid() >> 32;

    // https://github.com/torvalds/linux/blob/master/include/uapi/linux/in.h#L256
    // struct sockaddr_in* addr_in = (struct sockaddr_in*) addr;
    struct accept_sys_args accept_arg = {
        .addr = addr,
    };

    if (id == PID) {
        bpf_trace_printk("inside pid condition: %d,%d, %d", id, PID, sockfd);
        addr_in_s.update(&id, &accept_arg);
    }
    // https://github.com/torvalds/linux/blob/master/include/linux/socket.h#L191
}

// TODO: usar o ret_accept4 para o "time start"
void syscall__ret_accept4(struct pt_regs *ctx) {
    u32 id = bpf_get_current_pid_tgid() >> 32;

    struct accept_sys_args *accept = addr_in_s.lookup(&id);
    if (accept == NULL) {
        return;
    }

    struct sockaddr addr_n = {};

    bpf_probe_read_user(&addr_n, sizeof(addr_n), accept->addr);
    if (accept->addr != NULL) return;
}


// https://man7.org/linux/man-pages/man2/read.2.html
void syscall__read(struct pt_regs *ctx, int fd, void* buff, size_t count) {
    u32 id = bpf_get_current_pid_tgid() >> 32;
    u32 index = 0;

    void* lookup_res = addr_in_s.lookup(&id);
     if(lookup_res == NULL) {
         return;
     }

    struct accept_return* ret = returns.lookup(&index);
    if (ret == NULL) {
        return;
    }

    ret->size = count;
    ret->time = bpf_ktime_get_ns();
    bpf_probe_read_user(ret->request, sizeof(ret->request), buff);
    events.perf_submit(ctx, ret, sizeof(struct accept_return));
}

// https://man7.org/linux/man-pages/man2/close.2.html
void syscall__close(struct pt_regs *ctx) {
    u32 id = bpf_get_current_pid_tgid() >> 32;
    addr_in_s.delete(&id);
}


//https://man7.org/linux/man-pages/man7/bpf-helpers.7.html