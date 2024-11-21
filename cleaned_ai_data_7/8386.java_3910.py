class BaseInterfaceMsType:
    PDB_ID = 0x151a

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.attribute = ClassFieldMsAttributes(reader)
        self.base_class_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)
        numeric = Numeric(reader)
        if not numeric.is_integral():
            raise PdbException("Expecting integral numeric")
        self.offset = numeric.get_integral()
        reader.align4()

    def get_pdb_id(self):
        return self.PDB_ID

    def emit(self, builder, bind):
        self.attribute.emit(builder)
        builder.append(":")
        builder.append(pdb.get_type_record(self.base_class_record_number))
        builder.append("<@")
        builder.append(str(self.offset))
        builder.append(">")

class PdbException(Exception): pass
