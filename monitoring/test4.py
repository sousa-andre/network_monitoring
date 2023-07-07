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
    struct iov_entry *iov;
    struct iovec *msg_iov;
    unsigned int iov_count;

    if (bpf_probe_read_user(&iov, sizeof(iov), &msg->msg_iov)) {
        return 0;
    }

    if (bpf_probe_read_user(&msg_iov, sizeof(msg_iov), &iov->iov_base)) {
        return 0;
    }

    if (bpf_probe_read_user(&iov_count, sizeof(iov_count), &msg->msg_iovlen)) {
        return 0;
    }

    // Iterate over the iov array and print the data
    for (unsigned int i = 0; i < iov_count; i++) {
        if (bpf_probe_read_user(&ent, sizeof(ent), &msg_iov[i])) {
            continue;
        }

        char data[256];
        if (bpf_probe_read_user(data, sizeof(data), ent.iov_base)) {
            continue;
        }

        bpf_trace_printk("Received data: %s\\n", data);
    }

    return 0;
}
"""

# Load and attach the BPF program
b = BPF(text=bpf_code)
b.attach_kprobe(event="__sys_recvmsg", fn_name="kprobe_sys_recvmsg")

# Create a trace function to print the trace messages
def print_trace(cpu, data, size):
    print(b["output"].string)

# Add the trace function
b["output"].open_perf_buffer(print_trace)

# Sleep indefinitely, allowing the program to capture events
while True:
    b.perf_buffer_poll()
