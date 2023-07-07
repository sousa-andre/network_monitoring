from typing import Any, Dict, List

from bcc import BPF

from tracer.bpf.kprobe import KProbe


class Program:
    def __init__(self, file_path: str, variables: Dict[str, Any]):
        self._bpf = BPF(text=self.__class__.process_file(
            file_path,
            variables
        ))

    @staticmethod
    def process_file(file_path, variables):
        with open(file_path, 'r') as bpf_code:
            content = bpf_code.read()
            for key, value in variables.items():
                content = content.replace(f'#{key}#', value)
            return content

    def attach_kprobes(self, kprobes: List[KProbe]):
        for kprobe in kprobes:
            for kevent in kprobe.events:
                self._bpf.attach_kprobe(
                    event=self._bpf.get_syscall_fnname(kevent),
                    fn_name=kprobe.fnname
                )

    def poll_perf(self):
        while True:
            self._bpf.perf_buffer_poll()

    def perf_buffer(self, func):
        #def inner(data):
        #    self._bpf["events"].event(data)
#
        #    return
        self._bpf["events"].open_perf_buffer(func)
        return func
