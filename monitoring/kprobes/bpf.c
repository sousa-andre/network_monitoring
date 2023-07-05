#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/skbuff.h>

#define PID 341795

struct tcp_connect_args {
    struct sock *sock_p;
};

BPF_HASH(connections, u64, struct tcp_connect_args);

void kprobe_tcp_connect(struct pt_regs *ctx, struct sock *sock, struct sockaddr *uaddr, int addr_len) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    struct tcp_connect_args args = {
        .sock_p = sock
    };

    if (id == PID) {
        connections.update(&id, &args);
    }

    // bpf_trace_printk("sockfd: %d,%d, %d", pid, PID, id == PID);

}

void kprobe_ret_tcp_connect(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    struct tcp_connect_args *args = connections.lookup(&id);
    if (args == NULL) {
        return;
    }

    struct sock *sock_p = args->sock_p;

    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sock_p->__sk_common.skc_dport);
    bpf_trace_printk("dport: %d\n", ntohs(dport));

}


void kprobe_ret_tcp_recvmsg(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    struct tcp_connect_args *args = connections.lookup(&id);
    if (args == NULL) {
        return;
    }

    struct sock *sock_p = args->sock_p;

    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sock_p->__sk_common.skc_dport);
    bpf_trace_printk("dport2: %d\n", ntohs(dport));

    struct sk_buff_head socketbuff_head;
    bpf_probe_read_kernel(&socketbuff_head, sizeof(struct sk_buff_head), &sock_p->sk_receive_queue);

    struct sk_buff *sockbuff_p = skb_peek(&socketbuff_head);
    if (sockbuff_p != NULL) {
        char data[400];
        unsigned int len = 10;

        bpf_probe_read_user(data, sizeof(data), &sockbuff_p->data);
        bpf_probe_read_user(&len, sizeof(unsigned int), &sockbuff_p->len);
        bpf_trace_printk("sk_buff data: %s\n", data);
        bpf_trace_printk("sk_buff len: %d\n", len);
    }
}