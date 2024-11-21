class Ext4ExtentTail:
    def __init__(self, provider):
        self.eb_checksum = 0

    @classmethod
    def from_provider(cls, provider):
        reader = BinaryReader(provider)
        cls(reader)

    @classmethod
    def from_reader(cls, reader):
        cls.reader = reader
        cls.reader.read_int()

    @property
    def eb_checksum(self):
        return self._eb_checksum

    @eb_checksum.setter
    def eb_checksum(self, value):
        self._eb_checksum = value

    def to_data_type(self):
        structure = StructureDataType("ext4_extent_tail", 0)
        structure.add(DWORD, "eb_checksum")
        return structure


class BinaryReader:
    def __init__(self, provider):
        pass

    def read_int(self):
        # implement your logic here
        pass


DWORD = None  # replace with actual DWORD implementation in Python
StructureDataType = None  # replace with actual StructureDataType implementation in Python
