class ExceptionStateX86_64:
    def __init__(self):
        self.trapno = None
        self.err = None
        self.faultvaddr = None

    @classmethod
    def from_binary_reader(cls, reader):
        try:
            trapno = int.from_bytes(reader.read(4), 'little')
            err = int.from_bytes(reader.read(4), 'little')
            faultvaddr = int.from_bytes(reader.read(8), 'little')
            return cls(trapno, err, faultvaddr)
        except Exception as e:
            raise IOException(str(e))

    def to_data_type(self):
        from ghidra.util.data import StructureDataType
        struct = StructureDataType("x86_exception_state64", 0)
        struct.add(DWORD, "trapno")
        struct.add(DWORD, "err")
        struct.add(QWORD, "faultvaddr")
        return struct

class DWORD:
    def __init__(self):
        pass

class QWORD:
    def __init__(self):
        pass
