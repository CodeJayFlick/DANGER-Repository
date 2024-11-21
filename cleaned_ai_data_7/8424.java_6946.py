class EnumStMsType:
    PDB_ID = 0x1007

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.count = reader.parse_unsigned_short_val()
        self.property = MsProperty(reader)
        self.underlying_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)
        self.field_descriptor_list_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)
        self.name = reader.parse_string(pdb, 'StringSt')
        reader.skip_padding()

    def get_pdb_id(self):
        return self.PDB_ID

class MsProperty:
    pass

class RecordNumber:
    @staticmethod
    def parse(pdb, reader, category, size):
        # implement the parsing logic here
        pass

def main():
    pdb = 'your_pdb_here'
    reader = PdbByteReader()  # assume this class exists and has a method to read bytes from a file or stream
    enum_st_ms_type = EnumStMsType(pdb, reader)
    print(enum_st_ms_type.get_pdb_id())

if __name__ == '__main__':
    main()
