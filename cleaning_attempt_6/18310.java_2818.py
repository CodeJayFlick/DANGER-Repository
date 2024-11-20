class PublicBAOS:
    def __init__(self):
        self.buf = bytearray()

    def getBuf(self):
        return self.buf

    def writeTo(self, out):
        out.write(self.buf)

    def reset(self):
        self.buf = bytearray()
        self.count = 0

    @property
    def size(self):
        return len(self.buf)

    def truncate(self, size):
        self.buf = self.buf[:size]
