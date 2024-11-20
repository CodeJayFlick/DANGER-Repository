class MemoryInputStream:
    def __init__(self, mem, set):
        self.it = iter(mem.get_bytes(set))

    def read(self) -> int:
        try:
            if self.it:
                return next(self.it)
            else:
                return -1
        except StopIteration:
            raise IOError("End of file reached")
