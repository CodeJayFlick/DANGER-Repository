class VirtualFunctionTable32MsSymbol:
    PDB_ID = 0x100c

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.root_type_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)
        self.path_type_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)
        self.offset = reader.parse_var_sized_offset(32)
        self.segment = pdb.parse_segment(reader)

    def get_pdb_id(self):
        return self.PDB_ID

    def get_symbol_type_name(self):
        return "VFTABLE32"


class RecordNumber:
    @staticmethod
    def parse(pdb, reader, category, size):
        # Implement the logic to parse the record number here.
        pass


class PdbByteReader:
    def parse_var_sized_offset(self, size):
        # Implement the logic to parse variable sized offset here.
        pass

    def parse_segment(self, reader):
        # Implement the logic to parse segment here.
        pass
