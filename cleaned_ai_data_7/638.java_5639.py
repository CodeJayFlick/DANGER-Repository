class DbgReadPhysicalMemoryCommand:
    def __init__(self, manager, addr, buf, len):
        self.addr = addr
        self.buf = buf
        self.len = len
        super().__init__(manager)

    def complete(self, pending):
        range_set = set()
        range_set.add((self.addr, self.addr + self.read_len))
        return range_set

    def invoke(self):
        self.read_len = manager.get_data_spaces().read_physical(self.addr, self.buf, self.len)
