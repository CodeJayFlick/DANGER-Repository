class DefinedSingleAddressRangeMsSymbol:
    PDB_ID = 0x113f

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.program = reader.read_int()

    @property
    def pdb_id(self):
        return self.PDB_ID

    @property
    def symbol_type_name(self):
        return "DEFRANGE"

    def emit(self, builder):
        builder.append(f"{self.symbol_type_name}: DIA program NI: {self.program:04X}, ")
        self.emit_range_and_gaps(builder)
