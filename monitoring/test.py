from bcc import BPF

bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/uio.h>


struct iov_entry {
    void *iov_base;
    size_t iov_len;
};

BPF_HASH(sock_map, u64, struct socket *);

int kprobe_sys_recvmsg(struct pt_regs *ctx, int sockfd, struct msghdr *msg, unsigned int flags) {
    struct socket **sock;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 pid = pid_tgid >> 32;

    sock = sock_map.lookup(&pid);
    if (!sock) {
        return 0;
    }

    struct iov_entry ent;
    struct iov_iter *iter = &msg->msg_iter;

    // Iterate over the iov_iter and print the data
    while (iov_iter_next(iter, &ent, sizeof(ent)) == sizeof(ent)) {
        char data[256];
        bpf_probe_read_user(data, sizeof(data), ent.iov_base);

        bpf_trace_printk("Received data: %s\\n", data);
    }

    return 0;
}
"""

# Load and attach the BPF program
b = BPF(text=bpf_code)
b.attach_kprobe(event="sys_recvmsg", fn_name="kprobe_sys_recvmsg")

# Create a trace function to print the trace messages
def print_trace(cpu, data, size):
    print(b["output"].string)

# Add the trace function
b["output"].open_perf_buffer(print_trace)

# Sleep indefinitely, allowing the program to capture events
while True:
    b.perf_buffer_poll()
