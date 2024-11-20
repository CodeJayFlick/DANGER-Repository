class BuildInformationMsSymbol:
    PDB_ID = 0x114c

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.item_record_number = RecordNumber.parse(pdb, reader, 'ITEM', 32)

    def get_pdb_id(self):
        return self.PDB_ID

    def getItemRecordNumber(self):
        return self.item_record_number

    def getItemString(self):
        return str(self.pdb.getTypeRecord(self.item_record_number))

    def emit(self, builder):
        builder.append(f"{self.getSymbolTypeName()}: {str(self.pdb.getTypeRecord(self.item_record_number))}\n")

    def getSymbolTypeName(self):
        return "BUILDINFO"


class RecordNumber:
    @staticmethod
    def parse(pdb, reader, category, size):
        # Implement the logic to parse the record number here.
        pass


class PdbByteReader:
    def read(self):
        # Implement the logic to read from a byte stream here.
        pass

class AbstractPdb:
    def getTypeRecord(self, item_record_number):
        # Implement the logic to get type record based on item record number here.
        pass
