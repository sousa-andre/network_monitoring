#include <uapi/linux/ptrace.h>


// BPF_HASH(accept_args_map, u64, struct accept_args_t);

int accept_syscall(struct pt_regs *ctx, int sockfd, int a) {
    //uint64_t id = bpf_get_current_pid_tgid();

    // struct accept_args_t accept_args = {};

    // accept_args_map.update(&id, &accept_args);
    // struct sockaddr_in* addr2 = addr;
    // accept_args.addr = addr;
    // struct sockaddr_in* addr2 = (struct sockaddr_in*)addr;
    bpf_trace_printk("ab: %dK", sockfd);

    return 0;
};