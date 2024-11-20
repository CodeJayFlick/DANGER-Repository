class ConstantPoolDoubleInfo:
    def __init__(self):
        self.high_bytes = None
        self.low_bytes = None

    def from_binary_reader(self, reader):
        super().__init__()
        self.high_bytes = int.from_bytes(reader.read(4), 'big')
        self.low_bytes = int.from_bytes(reader.read(4), 'big')

    @property
    def value(self):
        bits = (self.high_bytes << 32) + self.low_bytes & 0xffffffffL
        if bits == 0x7ff0000000000000:
            return float('inf')
        elif bits == 0xfff0000000000000:
            return -float('inf')
        elif (bits >= 0x7ff0000000000001) and (bits <= 0x7fffffffffffffff):
            return float('nan')
        elif (bits >= 0xfff0000000000001) and (bits <= 0xffffffffffffffff):
            return float('nan')
        else:
            s = -1 if bits & 0x80000000 else 1
            e = int((bits >> 52) & 0x7ff)
            m = bits & 0xfffffffffffffL | 0x10000000000000L if e == 0 else (bits & 0xfffffffffffffL) << 1
            return s * float.fromhex('p+{}e-1075'.format(format(m, '016x')))

    @property
    def raw_bytes(self):
        return ((self.high_bytes << 32) + self.low_bytes & 0xffffffffL)

    def __str__(self):
        return str(self.value)

    def to_data_type(self):
        name = "CONSTANT_Long_info"
        structure = StructureDataType(name, 0)
        structure.add(BYTE, 'tag', None)
        structure.add(DWORD, 'high_bytes', None)
        structure.add(DWORD, 'low_bytes', None)
        return structure
