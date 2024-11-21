class ChunkHeader:
    def __init__(self):
        self.chunk_type = None  # See SparseConstants.CHUNK_TYPE_*
        self.reserved1 = None
        self.chunk_sz = None  # number of blocks in output
        self.total_sz = None

    @classmethod
    def from_binary_reader(cls, reader):
        chunk_header = cls()
        chunk_header.chunk_type = reader.read_short()
        chunk_header.reserved1 = reader.read_short()
        chunk_header.chunk_sz = reader.read_int()
        chunk_header.total_sz = reader.read_int()
        return chunk_header

    @property
    def chunk_type(self):
        return self.chunk_type

    @property
    def reserved1(self):
        return self.reserved1

    @property
    def chunk_sz(self):
        return self.chunk_sz

    @property
    def total_sz(self):
        return self.total_sz


class BinaryReader:
    def __init__(self, provider):
        pass  # This is not implemented in the original code. It seems to be a custom class.

    def read_short(self):
        raise NotImplementedError("This method should be implemented")

    def read_int(self):
        raise NotImplementedError("This method should be implemented")


class DataType:
    @classmethod
    def from_chunk_header(cls, chunk_header):
        structure = {"chunk_header": {}}
        structure["chunk_header"]["chunk_type"] = "WORD"
        structure["chunk_header"]["reserved1"] = "WORD"
        structure["chunk_heaer"]["chunk_sz"] = "DWORD"
        structure["chunk_header"]["total_sz"] = "DWORD"
        return structure
