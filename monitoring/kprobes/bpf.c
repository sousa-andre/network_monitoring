#include <uapi/linux/ptrace.h>
#include <net/sock.h>

struct tcp_connect_args {
    struct sock *sock;
};


BPF_HASH(connections, u32, struct sock*);

void kprobe_tcp_connect(struct pt_regs *ctx, struct sock *sock, struct sockaddr *uaddr, int addr_len) {
    u32 id = bpf_get_current_pid_tgid() << 32;


    //bpf_trace_printk("%d", sock->__sk_common.skc_dport);
    // bpf_trace_printk("HERE");

    struct tcp_connect_args args = {
        .sock=sock,
    };

    connections.update(&id, &sock);
}

void kprobe_ret_tcp_connect(struct pt_regs *ctx) {
    u32 id = bpf_get_current_pid_tgid() << 32;

    struct sock **skpp = connections.lookup(&id);
    if (skpp == NULL) {
        return;
    }
    struct sock *skp = *skpp;

    u16 dport = skp->__sk_common.skc_dport;
    bpf_trace_printk("dport: %d", ntohs(dport));

    //bpf_trace_printk("%d", args->sock->__sk_common.skc_dport);
}

void kprobe_tcp_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
}

void kprobe_ret_tcp_rcv(struct pt_regs *ctx) {
}