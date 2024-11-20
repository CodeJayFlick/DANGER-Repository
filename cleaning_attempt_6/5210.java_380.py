class XCoffArchiveHeader:
    _20 = 20

    def __init__(self, provider):
        reader = BinaryReader(provider, False)

        self.fl_magic = reader.read_next_bytes(XCoffArchiveConstants.MAGIC_LENGTH)
        self.fl_memoff = reader.read_next_bytes(_20)
        self.fl_gstoff = reader.read_next_bytes(_20)
        self.fl_gst64off = reader.read_next_bytes(_20)
        self.fl_fstmoff = reader.read_next_bytes(_20)
        self.fl_lstmoff = reader.read_next_bytes(_20)
        self.fl_freeoff = reader.read_next_bytes(_20)

    def fl_magic(self):
        return ''.join(map(chr, self.fl_magic)).strip()

    def fl_memoff(self):
        return int(''.join(map(chr, self.fl_memoff)).strip(), 0)

    def fl_gstoff(self):
        return int(''.join(map(chr, self.fl_gstoff)).strip(), 0)

    def fl_gst64off(self):
        return int(''.join(map(chr, self.fl_gst64off)).strip(), 0)

    def fstmoff(self):
        return int(''.join(map(chr, self.fl_fstmoff)).strip(), 0)

    def lstmoff(self):
        return int(''.join(map(chr, self.fl_lstmoff)).strip(), 0)

    def fl_freeoff(self):
        return int(''.join(map(chr, self.fl_freeoff)).strip(), 0)
