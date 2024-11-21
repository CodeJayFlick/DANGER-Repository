class ChangeExecutionModel32MsSymbol:
    PDB_ID = 0x020a

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader, 32)
        self.parse_specifics(reader)

    def get_pdb_id(self):
        return self.PDB_ID

    def get_symbol_type_name(self):
        return "CEXMODEL32"

    def parse_specifics(self, reader):
        model = None
        subtype = None
        flag = None
        offset_to_function_table = None
        segment_of_function_table = None
        
        if model == 'COBOL':
            subtype = reader.parse_unsigned_short_val()
            flag = reader.parse_unsigned_short_val()

        elif model in ['PCODE', 'PCODE32MACINTOSH', 'PCODE32MACINTOSH_NATIVE_ENTRY_POINT']:
            offset_to_function_table = reader.parse_unsigned_int_val()
            segment_of_function_table = reader.parse_unsigned_short_val()

        # Add more cases as needed
