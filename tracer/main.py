from sqlalchemy.orm import Session

from tracer.bpf.kprobe import KProbe
from tracer.bpf.program import Program
from tracer.db.connections.connection import engine
from tracer.parser.request_parser import parse_request

bpf_program = Program('bpf.c', {
    'PID': '42823'
})

bpf_program.attach_kprobes([
    KProbe(events=['accept4', 'accept'], fnname='syscall__accept4'),
    KProbe(events=['read'], fnname='syscall__read'),
    KProbe(events=['close'], fnname='syscall__close')
])


@bpf_program.perf_buffer
def eevent(cpu, data, size):
    event = bpf_program._bpf["events"].event(data)
    raw_data = event.request.decode('utf-8')
    print('cpu', cpu, size)
    print('Raw data', event.request, event.time, int(event.time / 1e9))

    with Session(engine) as session:
        request = parse_request(raw_data)

        request_ent = request.to_request_entity()

        headers_ent = request.to_header_entities()
        for header_ent in headers_ent:
            header_ent.request = request_ent

        session.add(request_ent)
        session.add_all(headers_ent)
        session.commit()


bpf_program.poll_perf()
