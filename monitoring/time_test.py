from bcc import BPF


BPF(text='int kprobe__schedule(void *ctx) { u64 ts = bpf_ktime_get_ns(); bpf_trace_printk("%lld\\n", ts); return 0; }').trace_print()