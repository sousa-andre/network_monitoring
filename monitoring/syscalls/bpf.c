#include <uapi/linux/ptrace.h>
#include <linux/socket.h>

#define PID 146944

// https://github.com/openbsd/src/blob/master/sys/sys/_types.h#L61
// https://github.com/pixie-io/pixie/blob/main/src/stirling/source_connectors/socket_tracer/bcc_bpf/socket_trace.c

// TODO: replace with the proper header
// typedef unsigned int socklen_t;
#define socklen_t size_t

struct accept_sys_args {
    struct sockaddr* addr;
};


struct accept_return {
    char request[100];
};

BPF_HASH(addr_in_s, u32, struct accept_sys_args);
BPF_PERF_OUTPUT(events);


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
        bpf_trace_printk("sockfd: %d", sockfd);
        addr_in_s.update(&id, &accept_arg);
    }
    // https://github.com/torvalds/linux/blob/master/include/linux/socket.h#L191
}

void syscall__ret_accept4(struct pt_regs *ctx) {
    u32 id = bpf_get_current_pid_tgid() >> 32;
    struct accept_sys_args *accept = addr_in_s.lookup(&id);
    if (accept == NULL) {
        return;
    }

    struct sockaddr addr_n = {};
     bpf_probe_read_user(&addr_n, sizeof(addr_n), accept->addr);
     if (accept->addr != NULL) return;

     bpf_trace_printk("sockfd: %d %d", addr_n.sa_family, AF_INET);
}


// https://man7.org/linux/man-pages/man2/read.2.html
void syscall__read(struct pt_regs *ctx, int fd, void* buff, size_t count) {
    u32 id = bpf_get_current_pid_tgid() >> 32;
    void* lookup_res = addr_in_s.lookup(&id);
     if(lookup_res != NULL) {
         // bpf_trace_printk("read %s, %d - pid", buff, id);
         return;
     }

     //if (id  == 114672) {
         //bpf_trace_printk("here %d", id);
    //}

    struct accept_return ret = {.request = *(char*)buff};
    // bpf_probe_read_user(&ret.request, 200, buff);
    events.perf_submit(ctx, &ret, sizeof(ret));
}


//https://man7.org/linux/man-pages/man7/bpf-helpers.7.html