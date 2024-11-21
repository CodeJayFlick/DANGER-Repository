class SubstringListMsType:
    PDB_ID = 0x1604
    
    def __init__(self, pdb, reader):
        self.record_numbers = []
        
        count = reader.read_int()
        for i in range(count):
            a_record_number = RecordNumber.parse(pdb, reader, 'ITEM', 32)
            self.record_numbers.append(a_record_number)

    @property
    def list(self):
        return self.record_numbers

    def get_pdb_id(self):
        return self.PDB_ID

    def emit(self, builder, bind):
        for a_record_number in self.record_numbers:
            type = pdb.get_type_record(a_record_number)
            if not isinstance(type, StringIdMsType):
                return  # fail quietly
            builder.append(str(type))
