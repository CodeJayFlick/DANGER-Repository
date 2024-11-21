class SectionContribution400:
    def __init__(self):
        self.isect = None
        self.offset = None
        self.length = None
        self.characteristics = None
        self.imod = None

    def deserialize(self, reader):
        try:
            # print(reader.dump(0x200))
            self.isect = reader.parse_unsigned_short()
            reader.read_bytes(2)  # I think there is padding here.
            self.offset = reader.parse_int()
            self.length = reader.parse_int()
            self.characteristics = reader.parse_unsigned_int()
            self.imod = reader.parse_unsigned_short()
        except Exception as e:
            raise PdbException(str(e))

    def dump internals(self):
        builder = StringBuilder("isect: ")
        builder.append(str(self.isect))
        builder.append("\noffset: ")
        builder.append(str(self.offset))
        builder.append("\nlength: ")
        builder.append(str(self.length))
        builder.append(String.format("\ncharacteristics: 0X%08X", self.characteristics))
        builder.append("\nimod: ")
        builder.append(str(self.imod))
        return str(builder)
