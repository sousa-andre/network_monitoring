from bcc import BPF, USDT


def main():
    print("Running guide")
    bpf = BPF(src_file='bpf/bpf_guide.c')


    print(bpf.get_syscall_fnname('sys_accept'))
    bpf.attach_kprobe(
        event=bpf.get_syscall_fnname('accept'),
        fn_name='accept_syscall'
    )

    while True:
        fields = bpf.trace_fields()
        print("fields", fields)


if __name__ == '__main__':
    main()
