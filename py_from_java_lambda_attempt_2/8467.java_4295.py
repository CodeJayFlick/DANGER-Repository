Here is the translation of the given Java code into Python:

```Python
class NestedTypeMsType:
    PDB_ID = 0x1510

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        reader.read(2)  # Throw away 2 bytes.
        self.nested_type_definition_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)
        self.name = reader.read_string(pdb, StringParseType.StringNt)
        reader.align4()

    def get_pdb_id(self):
        return self.PDB_ID


class AbstractPdb:
    pass


class PdbByteReader:
    def read_bytes(self, bytes_to_read):
        # implement this method
        pass

    def parse_string(self, pdb, string_parse_type):
        # implement this method
        pass

    def align4(self):
        # implement this method
        pass


class RecordNumber:
    @staticmethod
    def parse(pdb, reader, record_category, size):
        # implement this method
        pass


class StringParseType:
    StringNt = 'StringNt'
```

Please note that the above Python code is a direct translation of your Java code. However, it does not include any implementation for methods like `read_bytes`, `parse_string`, and `align4` in classes `PdbByteReader`, as these are specific to your application's requirements.