#include <uapi/linux/ptrace.h>
#include <linux/socket.h>
#include <linux/in.h>

#define PORT #PORT#

// https://github.com/openbsd/src/blob/master/sys/sys/_types.h#L61
// https://github.com/pixie-io/pixie/blob/main/src/stirling/source_connectors/socket_tracer/bcc_bpf/socket_trace.c

#define socklen_t size_t

struct accept_sys_args {
    u16 sin_port
    u64 accept_ts;
};

struct accept_return {
    u64 time_diff;
    char request[1024];
    unsigned int size;
};

BPF_HASH(addr_in_s, u32, struct accept_sys_args);
BPF_ARRAY(returns, struct accept_return, 1);
BPF_PERF_OUTPUT(events);

// https://man7.org/linux/man-pages/man2/bind.2.html
void syscall__bind(struct pt_regs *ctx, int sockfd, struct sockaddr *addr) {
    u32 id = bpf_get_current_pid_tgid() >> 32;
    unsigned short port;
    struct sockaddr_in* addr_in;

    if (addr->sa_family != AF_INET) return;
    addr_in = (struct sockaddr_in*)addr;

    bpf_probe_read_user(&port, sizeof(port), &addr_in->sin_port);
    // bpf_trace_printk("port %d", htons(port));

    struct accept_sys_args accept_arg  = {
       .sin_port = port
    };

   if (htons(accept_arg.sin_port) == PORT) {
        // bpf_trace_printk("saved port");
        addr_in_s.update(&id, &accept_arg);
   }
}

void syscall__accept4(
    struct pt_regs *ctx,
    int sockfd,
    // https://github.com/torvalds/linux/blob/master/include/linux/socket.h#L34
    struct sockaddr* addr,
    socklen_t* addrlen
    ) {
        u32 id = bpf_get_current_pid_tgid() >> 32;

    struct accept_sys_args* accept = addr_in_s.lookup(&id);
    if (accept == NULL) return;
    accept->accept_ts = bpf_ktime_get_ns();
   // bpf_trace_printk("accept yo");

    // https://github.com/torvalds/linux/blob/master/include/uapi/linux/in.h#L256

    // https://github.com/torvalds/linux/blob/master/include/linux/socket.h#L191
}

void syscall__read(struct pt_regs *ctx, int fd, void* buff, size_t count) {
    u32 id = bpf_get_current_pid_tgid() >> 32;
    u32 index = 0;

    struct accept_sys_args* lookup_res = addr_in_s.lookup(&id);
     if(lookup_res == NULL) {
         return;
     }

     //bpf_trace_printk("ABC '%s'", (char*)buff);

    struct accept_return* ret = returns.lookup(&index);
    if (ret == NULL) {
        return;
    }

    ret->size = count;
    ret->time_diff = bpf_ktime_get_ns() - lookup_res->accept_ts;
    bpf_probe_read_user(ret->request, sizeof(ret->request), buff);
    events.perf_submit(ctx, ret, sizeof(struct accept_return));
}