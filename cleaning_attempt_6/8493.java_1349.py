class StaticMemberStMsType:
    PDB_ID = 0x1406

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)
        self.attribute = ClassFieldMsAttributes(reader)
        self.field_type_record_number = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32)
        self.name = reader.parse_string(pdb, StringParseType.StringSt)
        reader.align4()

    def get_pdb_id(self) -> int:
        return self.PDB_ID
