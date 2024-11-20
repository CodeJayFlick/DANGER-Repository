class OMFAlignSym:
    def __init__(self):
        self.length = 0
        self.pad = []

    @classmethod
    def create_omf_align_sym(cls, reader, ptr):
        omf_align_sym = cls()
        omf_align_sym.init_omf_align_sym(reader, ptr)
        return omf_align_sym

    def init_omf_align_sym(self, reader, ptr):
        self.length = reader.read_short(ptr)
        ptr += 2
        self.pad = reader.read_bytes(ptr, self.length)

    @property
    def pad(self):
        return self._pad

    def __init_pad__(self):
        if not hasattr(self, '_pad'):
            self._pad = []

    pad.__init__ = OMFAlignSym.__init_pad__

class BinaryReader:
    SIZEOF_SHORT = 2

    def read_short(self, ptr):
        # implement this method to read a short integer from the binary data
        pass

    def read_bytes(self, ptr, length):
        # implement this method to read a byte array from the binary data
        pass
