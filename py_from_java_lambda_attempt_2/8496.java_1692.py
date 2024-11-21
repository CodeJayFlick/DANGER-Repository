Here is the equivalent Python code:

```Python
class Structure16MsType:
    PDB_ID = 0x0005

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.count = reader.parse_unsigned_short_val()
        self.field_descriptor_list_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 16)
        self.property = MsProperty(reader)
        self.derived_from_list_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 16)
        self.v_shape_table_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 16)
        numeric = Numeric(reader)
        if not numeric.is_integral():
            raise PdbException("Expecting integral numeric")
        self.size = numeric.get_integral()
        self.name = reader.parse_string(pdb, "StringSt")

    def get_pdb_id(self):
        return self.PDB_ID

class MsProperty:
    def __init__(self, reader):
        pass  # This class is not implemented in the original code.

class RecordNumber:
    @staticmethod
    def parse(pdb, reader, category, value_type):
        pass  # This method is not implemented in the original code.

class Numeric:
    def __init__(self, reader):
        pass  # This class is not implemented in the original code.

    def is_integral(self):
        return True

    def get_integral(self):
        return None
```

Please note that I did not implement all classes and methods as they were not provided in the original Java code.