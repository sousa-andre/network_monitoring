from bcc import BPF
import ctypes as ct

# BPF program code
bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/net.h>
#include <linux/skbuff.h>

BPF_PERF_OUTPUT(events);

int trace_sys_recvmsg(struct pt_regs *ctx, int sockfd, struct msghdr *msg, unsigned int flags) {
    struct sk_buff_data {
        u32 len;
        char data[256];
    };

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 pid = pid_tgid >> 32;

    struct sk_buff *skb = (struct sk_buff *)msg->msg_iter.kvec->iov_base;
    struct sk_buff_data data = {};

    bpf_probe_read_user(&data.len, sizeof(data.len), &skb->len);
    bpf_probe_read_user_str(&data.data, sizeof(data.data), skb->data);

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# Define the event structure
class Event(ct.Structure):
    _fields_ = [
        ("len", ct.c_uint32),
        ("data", ct.c_char * 256)
    ]

# Load the BPF program
b = BPF(text=bpf_code)

# Attach the kprobe
b.attach_kprobe(event="sys_recvmsg", fn_name="trace_sys_recvmsg")

# Get the event map
event_map = b.get_table("events")

# Define the event processing function
def print_request(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Event)).contents
    print(f"Received data: {event.data[:event.len]}")

# Process the captured events
b["events"].open_perf_buffer(print_request)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
