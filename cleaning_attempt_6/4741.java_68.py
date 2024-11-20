class GnuVerdaux:
    def __init__(self):
        self.vda_name = 0
        self.vda_next = 0

    @classmethod
    def from_binary_reader(cls, reader):
        try:
            vda_name = int.from_bytes(reader.read(4), 'little')
            vda_next = int.from_bytes(reader.read(4), 'little')
            return cls()
        except Exception as e:
            raise IOException(str(e))

    @property
    def get_vda_name(self):
        return self.vda_name

    @get_vda_name.setter
    def set_vda_name(self, value):
        self.vda_name = value

    @property
    def get_vda_next(self):
        return self.vda_next

    @get_vda_next.setter
    def set_vda_next(self, value):
        self.vda_next = value


class ElfVerdauxDataType:
    def __init__(self):
        pass

    def to_data_type(self):
        from ghidra.util.data import StructureDataType
        struct = StructureDataType("Elf_Verdaux", 0)
        struct.add('vna_name', 'Version or dependency names')
        struct.add('vna_next', 'Offset in bytes to next verdaux entry')
        return struct

