from datetime import datetime
from sys import argv
from time import time_ns

from sqlalchemy.orm import Session

from tracer.tracer.bpf.kprobe import KProbe
from tracer.tracer.bpf.program import Program
from tracer.tracer.db.connections.connection import engine
from tracer.tracer.parser.request_parser import parse_request
from tracer.tracer.utils.nanoseconds_splitter import nanoseconds_splitter

print(f'Attaching PORT {argv[1]}')
bpf_program = Program('bpf.c', {
    'PORT': argv[1],
})

bpf_program.attach_kprobes([
    KProbe(events=['bind'], fnname='syscall__bind'),
    KProbe(events=['accept4', 'accept'], fnname='syscall__accept4'),
    KProbe(events=['read'], fnname='syscall__read'),
])


@bpf_program.perf_buffer
def eevent(cpu, data, size):
    event = bpf_program._bpf["events"].event(data)
    try:
        raw_data = event.request.decode('utf-8')
    except UnicodeDecodeError:
        return
    request = parse_request(raw_data)
    if request is None:
        return

    print('Raw data', raw_data)

    with Session(engine) as session:
        request_ent = request.to_request_entity()

        s, ns = nanoseconds_splitter(time_ns())
        date_time = datetime.fromtimestamp(s)

        request_ent.timestamp_seconds = s
        request_ent.timestamp_nanoseconds = ns
        request_ent.read_delta_nanoseconds = event.time_diff
        request_ent.readable_date = date_time.date()
        request_ent.readable_time = date_time.time()

        headers_ent = request.to_header_entities()
        for header_ent in headers_ent:
            header_ent.request = request_ent

        session.add(request_ent)
        session.add_all(headers_ent)
        session.commit()


print('Running bcc')
bpf_program.poll_perf()
#while True:
#    fields = bpf_program._bpf.trace_fields()

#    print(fields)
