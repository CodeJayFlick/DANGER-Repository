class StartSearchMsSymbol:
    PDB_ID = 0x0005

    def __init__(self, pdb, reader):
        self.start_sym = reader.parse_unsigned_int_val()
        self.segment = pdb.parse_segment(reader)

    @property
    def pdb_id(self):
        return self.PDB_ID

    def emit(self, builder):
        builder.append(f"Start search for segment 0x{self.segment:x} at 0x{self.start_sym:x}")

    def get_symbol_type_name(self):
        return "START_SEARCH"
