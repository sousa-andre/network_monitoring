from dataclasses import dataclass
from typing import Dict, Optional

from tracer.tracer.db.entities.header_entity import HeaderEntity
from tracer.tracer.db.entities.request_entity import RequestEntity


@dataclass
class Request:
    method: str
    path: str
    version: str
    headers: Dict[str, str]
    body: Optional[str]

    def to_request_entity(self):
        return RequestEntity(
            method=self.method,
            path=self.path,
            body=self.body,
        )

    def to_header_entities(self):
        return (HeaderEntity(
            key=key,
            value=value
        ) for key, value in self.headers.items())

