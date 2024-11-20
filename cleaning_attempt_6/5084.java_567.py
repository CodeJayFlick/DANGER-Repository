class OMFModule:
    def __init__(self):
        self.ovlNumber = 0
        self.iLib = 0
        self.cSeg = 0
        self.style = 0
        self.segDescArr = []
        self.name = ''

    @classmethod
    def create_OMF_Module(cls, reader, ptr, byteCount):
        omfModule = cls()
        omfModule.init_OMF_Module(reader, ptr, byteCount)
        return omfModule

    def init_OMF_Module(self, reader, ptr, byteCount):
        index = ptr

        self.ovlNumber = reader.read_short(index); index += 2
        self.iLib = reader.read_short(index); index += 2
        self.cSeg = reader.read_short(index); index += 2
        self.style = reader.read_short(index); index += 2

        self.segDescArr = [0] * (self.cSeg)

        for i in range(self.cSeg):
            segDescArr[i] = OMFSegDesc.create_OMF_Seg_Desc(reader, index)
            index += 8
        # why do we need to increment?????
        index += 1

        self.name = reader.read_ascii_string(index).decode('ascii')

    def get_ovlNumber(self):
        return self.ovlNumber

    def get_iLib(self):
        return self.iLib

    def get_style(self):
        return self.style

    def get_name(self):
        return self.name

    def get_OMF_Seg_Descs(self):
        return self.segDescArr


class OMFSegDesc:
    @classmethod
    def create_OMF_Seg_Desc(cls, reader, ptr):
        # implement this method as needed
        pass


def read_short(reader, index):
    return int.from_bytes(reader.read(2), 'little')


def read_ascii_string(reader, index):
    length = ord(reader.read(1))
    return reader.read(length).decode('ascii')
