class DefinedSingleAddressRange2005MsSymbol:
    PDB_ID = 0x1134

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.bytes = reader.parse_bytes_remaining()

    def get_pdb_id(self):
        return self.PDB_ID

    def emit(self, builder):
        builder.append(f"{self.get_symbol_type_name()}: <NO API DETAILS, {len(self.bytes)} BYTES>")

    def get_symbol_type_name(self):
        return "DEFRAMGE_2005"
