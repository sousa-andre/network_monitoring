from typing import Tuple


def nanoseconds_splitter(nanoseconds_timestamp: int) -> Tuple[int, int]:
    return nanoseconds_timestamp // 1000000, \
           nanoseconds_timestamp % 1000000
