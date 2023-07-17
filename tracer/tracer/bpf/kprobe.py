from dataclasses import dataclass
from typing import List


@dataclass
class KProbe:
    events: List[str]
    fnname: str
