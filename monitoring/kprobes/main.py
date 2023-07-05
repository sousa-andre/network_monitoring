from bcc import BPF


def main():
    bpf = BPF('bpf.c')

    bpf.attach_kprobe(
        event='tcp_v4_connect',
        fn_name='kprobe_tcp_connect'
    )
    # bpf.attach_kretprobe(
    #     event='tcp_v4_connect',
    #     fn_name='kprobe_ret_tcp_connect'
    # )

    # bpf.attach_kprobe(
    #     event='tcp_v4_rcv',
    #     fn_name='kprobe_tcp_rcv'
    # )

    # bpf.attach_kretprobe(
    #     event='recvmsg',
    #     fn_name='kprobe_ret_tcp_connect'
    # )

    bpf.attach_kretprobe(
        event='tcp_v4_rcv',
        fn_name='kprobe_ret_tcp_recvmsg'
    )

    print('running bpf code...')
    while True:
        print(bpf.trace_fields())


if __name__ == '__main__':
    main()
