class GdbMemoryMapping:
    def __init__(self, start: int, end: int, size: int, offset: int, objfile: str):
        self.start = start
        self.end = end
        self.size = size
        self.offset = offset
        self.objfile = objfile

        assert start + size == end

    @property
    def start(self) -> int:
        return self._start

    @property
    def end(self) -> int:
        return self._end

    @property
    def size(self) -> int:
        return self._size

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def objfile(self) -> str:
        return self._objfile


# Example usage:

gdb_mapping = GdbMemoryMapping(0, 1024*1024, 512*1024, 4096, 'example.obj')
print(gdb_mapping.start)
print(gdb_mapping.end)
print(gdb_mapping.size)
print(gdb_mapping.offset)
print(gdb_mapping.objfile)
