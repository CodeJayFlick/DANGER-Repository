import heapq
from typing import Any

class DescPriorityMergeReader:
    def __init__(self):
        self.heap = []

    def add_reader(self, reader: Any, priority: int, end_time: float, context: Any) -> None:
        if reader.has_next():
            element = (reader.next(), priority)
            heapq.heappush(self.heap, (-element[0][1], element))
            self.current_read_stop_time = min(self.current_read_stop_time, end_time)

    def current_read_stop_time(self):
        return 0.0

class Element:
    def __init__(self, reader: Any, pair: tuple, priority: int):
        self.reader = reader
        self.pair = pair
        self.priority = priority

    def curr_pair(self) -> tuple:
        return self.pair

    def get_priority(self) -> int:
        return self.priority
