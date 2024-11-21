Here is the translation of the given Java code into Python:

```Python
class OMFSegMapDesc:
    IMAGE_SIZEOF_OMF_SEG_MAP_DESC = 20

    def __init__(self):
        self.flags = None
        self.ovl = None
        self.group = None
        self.frame = None
        self.iSegName = None
        self.iClassName = None
        self.offset = None
        self.cbSeg = None

    @classmethod
    def create_OMFSegMapDesc(cls, reader, ptr):
        omfSegMapDesc = OMFSegMapDesc()
        omfSegMapDesc.init_OMFSegMapDesc(reader, ptr)
        return omfSegMapDesc

    def init_OMFSegMapDesc(self, reader, ptr):
        self.flags = reader.read_short(ptr); ptr += 2
        self.ovl = reader.read_short(ptr); ptr += 2
        self.group = reader.read_short(ptr); ptr += 2
        self.frame = reader.read_short(ptr); ptr += 2
        self.iSegName = reader.read_short(ptr); ptr += 2
        self.iClassName = reader.read_short(ptr); ptr += 2
        self.offset = reader.read_int(ptr); ptr += 4
        self.cbSeg = reader.read_int(ptr); ptr += 4

    def get_flags(self):
        return self.flags

    def get_logical_overlay_number(self):
        return self.ovl

    def get_group_index(self):
        return self.group

    def get_logical_segment_index(self):
        return self.frame

    def get_segment_name(self):
        return self.iSegName

    def get_class_name(self):
        return self.iClassName

    def get_byte_offset(self):
        return self.offset

    def get_byte_count(self):
        return self.cbSeg
```

Note: Python does not have direct equivalent of Java's `readShort()`, `readInt()` methods. The above code assumes that the reader object has these methods implemented to read short and int values from a file or stream.