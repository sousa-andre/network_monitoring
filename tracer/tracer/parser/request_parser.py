from typing import List

from tracer.tracer.parser.request import Request


def parse_request_header_until_body(lines: List[str]):
    headers = {}

    while len(lines) > 0 and (curr_line := lines.pop(0)) != '':
        split_pos = curr_line.find(':')
        key = curr_line[0:split_pos]
        value = curr_line[split_pos+1:].strip()

        headers[key] = value

    return headers


def parse_request(data: str):
    lines = data.splitlines()

    if len(lines) < 1:
        return None

    # first line
    [method, path, version] = lines.pop(0).split(' ')

    headers = parse_request_header_until_body(lines)
    body = lines[0] if len(lines) > 0 else None

    return Request(
        method=method,
        path=path,
        version=version,
        headers=headers,
        body=body,
    )

