class DbgReadMemoryCommand:
    def __init__(self, manager, addr, buf, len):
        self.manager = manager
        self.addr = addr
        self.buf = buf
        self.len = len
        self.read_len = 0

    def complete(self, pending=None):
        range_set = set()
        range_set.add((self.addr, self.addr + self.read_len))
        return range_set

    def invoke(self):
        self.read_len = self.manager.get_data_spaces().read_virtual(self.addr, self.buf, self.len)
