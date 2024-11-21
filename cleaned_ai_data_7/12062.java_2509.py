class InMemoryRangeMapAdapter:
    def __init__(self):
        self.range_map = {}

    def clear_range(self, start: int, end: int) -> None:
        if isinstance(start, str):  # Assuming Address type in Java has a to_int() method.
            start = int(start)
        if isinstance(end, str):
            end = int(end)

        for addr in range(start, end + 1):
            self.range_map.pop(addr, None)

    def clear_all(self) -> None:
        self.range_map.clear()

    def get_value_range_containing(self, address: int) -> tuple:
        return next((k, v) for k, v in self.range_map.items() if k <= address < (k + len(v)))

    def get_address_range_iterator(self, start: int = None, end: int = None) -> iter:
        yield from ((k, v) for k, v in self.range_map.items() if start is None or k >= start and end is None or k <= end)

    def get_value(self, address: int) -> bytes:
        return self.range_map.get(address - 1).get()

    def set(self, start: int, end: int, value: bytes) -> None:
        for addr in range(start, end + 1):
            if not isinstance(addr, str):  # Assuming Address type in Java has a to_int() method.
                self.range_map[addr - 1] = [value]

    def move_address_range(self, from_addr: int, to_addr: int, length: int) -> None:
        for addr in range(from_addr, from_addr + length):
            if not isinstance(addr, str):  # Assuming Address type in Java has a to_int() method.
                self.range_map[addr - 1] = [self.range_map.get(to_addr - 1).get()]

    def is_empty(self) -> bool:
        return len(self.range_map) == 0

    def check_writable_state(self):
        pass
