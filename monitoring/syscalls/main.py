from bcc import BPF


def main():
    start = 0

    def print_event(cpu, data, size):
        event = bpf["events"].event(data)
        print(event)

    bpf = BPF('bpf.c')

    accept4_fnname = bpf.get_syscall_fnname('accept4')
    bpf.attach_kprobe(
        event=accept4_fnname,
        fn_name='syscall__accept4'
    )

    bpf.attach_kretprobe(
        event=accept4_fnname,
        fn_name='syscall__ret_accept4'
    )

    # read_fname = bpf.get_syscall_fnname('read')
    # bpf.attach_kprobe(
    #     event=read_fname,
    #     fn_name='syscall__read'
    # )

    bpf['events'].open_perf_buffer(print_event)
    while True:
        print("trace", bpf.trace_fields())
        #bpf.perf_buffer_poll()


if __name__ == '__main__':
    main()
