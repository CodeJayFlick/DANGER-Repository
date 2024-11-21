Here is the translation of the given Java code into equivalent Python:

```Python
class Class19MsType:
    PDB_ID = 0x1608

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.property = MsProperty(reader)
        x = reader.parse_unsigned_short_val()  # unknown
        self.field_descriptor_list_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)
        self.derived_from_list_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)
        self.v_shape_table_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)

    def get_pdb_id(self):
        return self.PDB_ID

class MsProperty:
    pass

class RecordNumber:
    @staticmethod
    def parse(pdb, reader, category, size):
        # implement parsing logic here
        pass

class Numeric:
    def __init__(self, reader):
        self.value = reader.parse_unsigned_short_val()  # unknown. Might even be just a short.

    def is_integral(self):
        return True

    def get_integral(self):
        return self.value


# usage example
pdb = 'your_pdb_file'
reader = PdbByteReader(pdb)
class19msType = Class19MsType(pdb, reader)

print(class19msType.get_pdb_id())
```

Please note that this is a direct translation of the Java code into Python. You might need to adjust it according to your specific requirements and the actual implementation details (e.g., `PdbByteReader`, `RecordNumber.parse` method).