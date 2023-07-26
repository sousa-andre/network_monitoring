from typing import Tuple


def nanoseconds_splitter(nanoseconds_timestamp: int) -> Tuple[int, int]:
    ratio = 1000000000
    return nanoseconds_timestamp // ratio, \
        nanoseconds_timestamp % ratio
