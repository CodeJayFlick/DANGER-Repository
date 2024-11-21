class OMFSegDesc:
    IMAGE_SIZEOF_OMF_SEG_DESC = 12

    def __init__(self):
        self.seg = None
        self.pad = None
        self.offset = None
        self.cbSeg = None

    @classmethod
    def createOMFSegDesc(cls, reader, index):
        omfSegDesc = OMFSegDesc()
        omfSegDesc.initOMFSegDesc(reader, index)
        return omfSegDesc

    def initOMFSegDesc(self, reader, index):
        self.seg = reader.read_short(index); index += 2
        self.pad = reader.read_short(index); index += 2
        self.offset = reader.read_int(index); index += 4
        self.cbSeg = reader.read_int(index); index += 4

    def get_segment_index(self):
        return self.seg

    def get_alignment_pad(self):
        return self.pad

    def get_offset(self):
        return self.offset

    def get_number_of_bytes(self):
        return self.cbSeg
