from datetime import datetime
from sys import argv
from time import time_ns

from sqlalchemy.orm import Session

from tracer.tracer.bpf.kprobe import KProbe
from tracer.tracer.bpf.program import Program
from tracer.tracer.db.connections.connection import engine
from tracer.tracer.parser.request_parser import parse_request
from tracer.tracer.utils.nanoseconds_splitter import nanoseconds_splitter


bpf_program = Program('bpf.c', {
    'PID': argv[1]
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

    with Session(engine) as session:
        request = parse_request(raw_data)

        request_ent = request.to_request_entity()

        s, ns = nanoseconds_splitter(time_ns())

        request_ent.timestamp_seconds = s
        request_ent.timestamp_nanoseconds = ns
        request_ent.read_delta_nanoseconds = event.time_diff
        request.readable_date_time = datetime.fromtimestamp(s)

        headers_ent = request.to_header_entities()
        for header_ent in headers_ent:
            header_ent.request = request_ent

        session.add(request_ent)
        session.add_all(headers_ent)
        session.commit()


bpf_program.poll_perf()
