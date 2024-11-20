class RegisterRelativeAddress32MsSymbol:
    PDB_ID = 0x1111

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.offset = reader.parse_var_sized_offset(32)
        self.type_record_number = RecordNumber().parse(pdb, reader, 'TYPE', 32)
        self.register_index = reader.parse_unsigned_short_val()
        self.name = reader.parse_string(pdb, StringParseType.STRING_UTF8_NT)
        reader.align4()
        self.register_name = RegisterName(pdb, self.register_index)

    def get_pdb_id(self):
        return self.PDB_ID

    def get_symbol_type_name(self):
        return "REGREL32"


class RecordNumber:
    @staticmethod
    def parse(pdb, reader, category, size):
        # This method is not implemented in the given Java code.
        pass


class RegisterName:
    def __init__(self, pdb, register_index):
        self.pdb = pdb
        self.register_index = register_index

# Define StringParseType and PdbByteReader classes if needed for further parsing operations.


if __name__ == "__main__":
    # Example usage of the class.
    pdb = "Your_PDB_object"
    reader = "Your_Reader_object"
    symbol = RegisterRelativeAddress32MsSymbol(pdb, reader)
