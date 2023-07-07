import unittest

from tracer.parser.request import Request
from tracer.parser.request_parser import parse_request


class TestRequestParser(unittest.TestCase):
    def test_get(self):
        value = parse_request(
            'GET / HTTP/1.1\r\nHost: localhost:8000\r\nUser-Agent: curl/7.87.0\r\nAccept: */*\r\n\r\n')

        expected = Request(
            method='GET',
            path='/',
            version='HTTP/1.1',
            headers={
                'Host': 'localhost:8000',
                'User-Agent': 'curl/7.87.0',
                'Accept': '*/*'},
            body=None
        )
        self.assertEqual(value, expected)

    def test_post_with_data(self):
        value = parse_request('POST / HTTP/1.1\r\nHost: localhost:8000\r\nUser-Agent: curl/7.87.0\r\nAccept: '
                              '*/*\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{"a": "b"}')

        expected = Request(
            method='POST',
            path='/',
            version='HTTP/1.1',
            headers={
                'Host': 'localhost:8000',
                'User-Agent': 'curl/7.87.0',
                'Accept': '*/*',
                'Content-Type': 'application/json',
                'Content-Length': '10'
            },
            body='{"a": "b"}'
        )

        self.assertEqual(value, expected)
