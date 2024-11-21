class SectionContribution600:
    def __init__(self):
        self.isect = None
        self.offset = None
        self.length = None
        self.characteristics = None
        self.imod = None
        self.dataCrc = None
        self.relocationCrc = None

    def deserialize(self, reader):
        try:
            # System.out.println(reader.dump(0x200));
            self.isect = reader.parse_unsigned_short()
            reader.read_bytes(2)  # I think there is padding here.
            self.offset = reader.parse_int()
            self.length = reader.parse_int()
            self.characteristics = reader.parse_unsigned_int()
            imod = reader.parse_unsigned_short()
            reader.align4()  # Not sure what this does
            self.dataCrc = reader.parse_unsigned_int()
            self.relocationCrc = reader.parse_unsigned_int()
        except Exception as e:
            print(f"Error deserializing: {e}")

    def dumpInternals(self):
        builder = StringBuilder()
        builder.append("isect: ")
        builder.append(str(self.isect))
        builder.append("\noffset: ")
        builder.append(str(self.offset))
        builder.append("\nlength: ")
        builder.append(str(self.length))
        builder.append(f"\ncharacteristics: 0x{self.characteristics:x}")
        builder.append("\nimod: ")
        builder.append(str(self.imod))
        builder.append("\ndataCrc: ")
        builder.append(str(self.dataCrc))
        builder.append("\nrelocationCrc: ")
        builder.append(str(self.relocationCrc))
        return str(builder)
