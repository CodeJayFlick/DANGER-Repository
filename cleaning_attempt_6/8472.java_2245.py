class OemDefinableString2MsType:
    PDB_ID = 0x1011
    
    def __init__(self):
        self.guid = None
        self.record_numbers = []
        self.remaining_bytes = []

    def from_pdb(self, pdb_reader: 'PdbByteReader') -> None:
        super().__init__()
        self.guid = pdb_reader.parse_guid()
        count = pdb_reader.parseInt()
        for _ in range(count):
            record_number = RecordNumber.from_pdb(pdb_reader)
            self.record_numbers.append(record_number)
        self.remaining_bytes = pdb_reader.parse_remaining_bytes()

    def to_string(self) -> str:
        return f"OEM Definable String 2\n" \
               f" GUID: {self.guid}\n" \
               f" count: {len(self.record_numbers)}\n"
        for i, record_number in enumerate(self.record_numbers):
            self.to_string += f"    recordNumber[{i}]: 0x{record_number.get_number():08x}\n"
        return self.to_string + f"  additional data length: {len(self.remaining_bytes)}\n"

class RecordNumber:
    @classmethod
    def from_pdb(cls, pdb_reader):
        # assuming there's a method to parse the record number in PDB format
        pass

class GUID:
    def __init__(self):
        self.guid = None
    
    def to_string(self) -> str:
        return f"{self.guid}"
