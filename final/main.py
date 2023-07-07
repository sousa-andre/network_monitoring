from bcc import BPF


def main():
    bpf = BPF('bpf.c')

    def print_event(cpu, data, size):
        event = bpf["events"].event(data)
        print(event.request, "size", event.size, "time", event.time)

    # accept syscall
    accept4_fnname = bpf.get_syscall_fnname('accept4')
    accept_fnname = bpf.get_syscall_fnname('accept')

    bpf.attach_kprobe(
        event=accept4_fnname,
        fn_name='syscall__accept4'
    )
    bpf.attach_kprobe(
        event=accept_fnname,
        fn_name='syscall__accept4'
    )

    bpf.attach_kretprobe(
        event=accept4_fnname,
        fn_name='syscall__ret_accept4'
    )
    bpf.attach_kprobe(
        event=accept_fnname,
        fn_name='syscall__ret_accept4'
    )

    # read syscall
    read_fname = bpf.get_syscall_fnname('read')
    bpf.attach_kprobe(
        event=read_fname,
        fn_name='syscall__read'
    )

    # close syscall
    close_fname = bpf.get_syscall_fnname('close')
    bpf.attach_kprobe(
        event=close_fname,
        fn_name='syscall__close'
    )

    bpf["events"].open_perf_buffer(print_event)
    while True:
        bpf.perf_buffer_poll()


if __name__ == '__main__':
    main()
