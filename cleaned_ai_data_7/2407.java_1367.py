class DBTraceMemBuffer:
    def __init__(self, space: 'DBTraceMemorySpace', snap: int, start: 'Address', byte_order: str):
        self.space = space
        self.snap = snap
        self.start = start
        self.byte_order = byte_order

    @property
    def address(self) -> 'Address':
        return self.start

    def get_memory(self) -> 'Memory':
        # TODO: This may be problematic for non-canonical views
        return self.space.trace.get_program_view().get_memory()

    def is_big_endian(self) -> bool:
        return self.byte_order == "big-endian"

    def read_bytes(self, buffer: bytes, offset: int) -> int:
        try:
            return self.space.view_bytes(self.snap, self.start.add_no_wrap(offset), buffer)
        except AddressOverflowException as e:
            return 0
