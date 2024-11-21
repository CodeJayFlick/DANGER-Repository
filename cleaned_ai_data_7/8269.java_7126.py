class PeCoffSectionMsSymbol:
    PDB_ID = 0x1136

    def __init__(self):
        self.section_number = None
        self.align = None
        self.reserved = None
        self.rva = None
        self.length = None
        self.characteristics = None
        self.name = None

    @staticmethod
    def from_pdb(pdb, reader):
        symbol = PeCoffSectionMsSymbol()
        super().__init__(pdb)
        symbol.section_number = pdb.parse_segment(reader)  # TODO: confirm... assuming segment
        symbol.align = reader.read_unsigned_byte_val()
        symbol.reserved = reader.read_unsigned_byte_val()
        symbol.rva = reader.read_int()
        symbol.length = reader.read_int()
        symbol.characteristics = reader.read_int()
        symbol.name = reader.read_string(pdb, 'StringUtf8Nt')
        reader.align4()

    def get_pdb_id(self):
        return self.PDB_ID

    @property
    def section_number(self):
        return self.section_number

    @section_number.setter
    def section_number(self, value):
        self.section_number = value

    @property
    def align(self):
        return self.align

    @align.setter
    def align(self, value):
        self.align = value

    @property
    def reserved(self):
        return self.reserved

    @reserved.setter
    def reserved(self, value):
        self.reserved = value

    @property
    def rva(self):
        return self.rva

    @rva.setter
    def rva(self, value):
        self.rva = value

    @property
    def length(self):
        return self.length

    @length.setter
    def length(self, value):
        self.length = value

    @property
    def characteristics(self):
        return self.characteristics

    @characteristics.setter
    def characteristics(self, value):
        self.characteristics = value

    @property
    def name(self):
        return self.name

    @name.setter
    def name(self, value):
        self.name = value

    def emit(self, builder):
        builder.append(f"{self.get_symbol_type_name()}: [{self.section_number:04X}], RVA = {self.rva:08x}, Length = {self.length:08X}, Align = {self.align:08X}, Characteristics = {self.characteristics:08X}, {self.name}")

    def get_symbol_type_name(self):
        return "SECTION"

# Example usage:
class Pdb:
    @staticmethod
    def parse_segment(reader):
        # Your code here

    @staticmethod
    def read_unsigned_byte_val():
        # Your code here

    @staticmethod
    def read_int():
        # Your code here

    @staticmethod
    def read_string(pdb, string_type):
        # Your code here

    @staticmethod
    def align4():
        # Your code here


# Usage:
pdb = Pdb()
reader = Reader()  # You need to implement this class as well.
symbol = PeCoffSectionMsSymbol.from_pdb(pdb, reader)
print(symbol.emit(StringBuilder()))
