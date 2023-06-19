from bcc import BPF

# Define the eBPF program code
bpftext = """
#include <linux/sched.h>

int kretprobe__do_exit(struct pt_regs *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_trace_printk("Exit status code: %d\\n", task->exit_code);
    return 0;
}
"""

def main():
    bpf = BPF(text=bpftext)
    bpf.attach_kretprobe(event="atexit", fn_name="kretprobe__do_exit")

    print("Monitoring process exits. Press Ctrl+C to exit.")
    try:
        while True:
            (_, _, _, _, msg) = bpf.trace_fields()
            print(msg.decode('utf-8'))
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
