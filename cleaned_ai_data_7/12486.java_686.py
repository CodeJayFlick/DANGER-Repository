class PackedBytes:
    def __init__(self, startlen):
        self.out = bytearray(startlen)
        self.bytecnt = 0

    def size(self):
        return self.bytecnt

    def get_byte(self, streampos):
        return self.out[streampos]

    def insert_byte(self, streampos, val):
        self.out[streampos] = val & 0xFF

    def write(self, val):
        newcount = self.bytecnt + 1
        if newcount > len(self.out):
            self.out = bytearray(max(len(self.out) * 2, newcount))
        self.out[self.bytecnt] = val & 0xFF
        self.bytecnt = newcount

    def find(self, start, val):
        while start < self.bytecnt:
            if self.out[start] == val:
                return start
            start += 1
        return -1

    def write_to(self, s):
        s.write(bytearray(self.out[:self.bytecnt]))
