class SegmentMapDescription:
    def __init__(self):
        self.flags = 0
        self.ovl = 0
        self.group = 0
        self.frame = 0
        self.segNameIndex = 0
        self.classNameIndex = 0
        self(segOffset=0, segLength=0)

    def get_segment_offset(self):
        return self.segOffset

    def get_length(self):
        return self.segLength

    @classmethod
    def deserialize(cls, substream_reader):
        try:
            cls.flags = substream_reader.parse_unsigned_short()
            cls.ovl = substream_reader.parse_unsigned_short()
            cls.group = substream_reader.parse_unsigned_short()
            cls.frame = substream_reader.parse_unsigned_short()
            cls.segNameIndex = substream_reader.parse_unsigned_short()
            cls.classNameIndex = substream_reader.parse_unsigned_short()
            cls.segOffset = substream_reader.parse_unsigned_int()
            cls.segLength = substream_reader.parse_unsigned_int()
        except Exception as e:
            raise PdbException("Not enough data left to parse.") from e

    def dump(self):
        return f"SegmentMapDescription---------------------------------------\nflags: {self.flags}\novl: {self.ovl}\ngroup: {self.group}\nframe: {self.frame}\nsegNameIndex: {self.segNameIndex}; classNameIndex: {self.classNameIndex}; segOffset: {self.segOffset}; segLength: {self.segLength}"
