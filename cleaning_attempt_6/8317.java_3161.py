class VirtualFunctionTable16MsSymbol:
    PDB_ID = 0x010b

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.offset = reader.parse_var_sized_offset(16)
        self.segment = pdb.parse_segment(reader)
        self.root_type_record_number = RecordNumber().parse(pdb, reader, 'TYPE', 16)
        self.path_type_record_number = RecordNumber().parse(pdb, reader, 'TYPE', 16)

    def get_pdb_id(self):
        return self.PDB_ID

    def get_symbol_type_name(self):
        return "VFTABLE16"


class AbstractPdb:
    pass


class PdbByteReader:
    def parse_var_sized_offset(self, size):
        # Implement this method
        pass


class RecordNumber:
    @staticmethod
    def parse(pdb, reader, category, size):
        # Implement this method
        pass


# Example usage:

pdb = AbstractPdb()
reader = PdbByteReader()

symbol = VirtualFunctionTable16MsSymbol(pdb, reader)
print(symbol.get_pdb_id())
