class TypeServer2MsType:
    PDB_ID = 0x1515

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.signature = reader.parse_guid()
        self.age = reader.parse_unsigned_int_val()
        self.name = reader.parse_string(pdb, "StringNt")

    @property
    def pdb_id(self):
        return self.PDB_ID

    def emit(self, builder, bind):
        # There is no documented API.
        builder.append(f"<<{self.__class__.__name__} {self.name} {self.signature} {self.age}>>")


# Note: This Python code does not include the GUID and PdbByteReader classes as they are not provided in the original Java code. You would need to implement these classes or use existing ones for this translation.
