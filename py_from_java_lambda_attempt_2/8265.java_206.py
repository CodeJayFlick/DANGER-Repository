Here is the translation of the given Java code into equivalent Python:

```Python
class OemDefinedMsSymbol:
    PDB_ID = 0x0404
    
    SSOEMID_GUID_PARTS = bytes([0xbc, 0x25, 0x09, 0x02, 0xbb, 0xab, 0xb4, 0x60])
    
    def __init__(self):
        self.oem_id = None
        self.type_record_number = None
        self.user_data = []

    def from_pdb_reader(self, pdb, reader):
        super().__init__()
        
        data1 = int.from_bytes(reader.read(4), 'little')
        data2 = int.from_bytes(reader.read(2), 'little') & 0xFFFF
        data3 = int.from_bytes(reader.read(2), 'little') & 0xFFFF
        self.oem_id = GUID(data1, data2, data3, SSOEMID_GUID_PARTS)
        
        self.type_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)
        
        while reader.has_more():
            val = int.from_bytes(reader.read(4), 'little')
            self.user_data.append(val)

    def get_pdb_id(self):
        return OemDefinedMsSymbol.PDB_ID

    def emit(self, builder):
        builder.write(f"{self.get_symbol_type_name()}: {str(self.oem_id)}, Type {pdb.getTypeRecord(self.type_record_number)}\n")
        
        if self.oem_id == SSOEMID:
            for val in self.user_data:
                builder.write(f"   {val:08X}\n")

    def get_symbol_type_name(self):
        return "OEM"

class GUID:
    def __init__(self, data1, data2, data3, guid_parts):
        self.data1 = data1
        self.data2 = data2
        self.data3 = data3
        self.guid_parts = bytes([data1 >> 24, (data1 >> 16) & 0xFF,
                                 (data1 >> 8) & 0xFF, data1 & 0xFF,
                                 data2 >> 8, data2 & 0xFF,
                                 data3 >> 8, data3 & 0xFF]) + guid_parts

    def __eq__(self, other):
        return self.data1 == other.data1 and self.data2 == other.data2 and self.data3 == other.data3 and self.guid_parts == other.guid_parts

class RecordNumber:
    @staticmethod
    def parse(pdb, reader, category, size):
        # This is a placeholder for the actual parsing logic.
        return 0

class PdbByteReader:
    def read(self, size):
        raise NotImplementedError("Subclasses must implement this method")

    def has_more(self):
        raise NotImplementedError("Subclasses must implement this method")
```

This Python code does not include all of the Java classes and methods. It only includes those that are necessary to translate the given Java class into equivalent Python.