class VirtualFunctionTablePointer16MsType:
    PDB_ID = 0x040a

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.pointer_type_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 16)
        reader.skip_padding()

    def get_pdb_id(self):
        return self.PDB_ID


class AbstractPdb:
    pass


class PdbByteReader:
    def skip_padding(self):
        pass

    @staticmethod
    def parse(pdb, reader, category, size):
        raise NotImplementedError("Not implemented")


class RecordNumber:
    @classmethod
    def parse(cls, pdb, reader, category, size):
        return None  # Not implemented


# Example usage:

pdb = AbstractPdb()
reader = PdbByteReader()

vft_pointer = VirtualFunctionTablePointer16MsType(pdb, reader)
print(vft_pointer.get_pdb_id())
