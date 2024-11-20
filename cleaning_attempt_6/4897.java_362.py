class RelocationOSFixup:
    def __init__(self, reader):
        self.fixup_type = reader.read_short()
        self.zeropad = reader.read_short()

    @property
    def fixup_type(self):
        return self.fixup_type

    @property
    def pad(self):
        return self.zeropad


class BinaryReader:
    def read_short(self):
        # implement reading a short integer from the binary data
        pass
