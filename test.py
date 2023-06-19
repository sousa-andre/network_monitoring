from bcc import BPF


def main():
    bpftext = """
    #include <uapi/linux/ptrace.h>

    void syscall__a(struct pt_regs *ctx, int status){
        u64 pid = bpf_get_current_pid_tgid();
       
    }
    """

    bpf = BPF(text=bpftext)
    bpf.attach_kprobe(fn_name='syscall__a', event=bpf.get_syscall_fnname('accept'))

    while True:
        print(bpf.trace_fields())


if __name__ == '__main__':
    main()
