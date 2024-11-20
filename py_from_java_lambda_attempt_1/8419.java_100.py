Here is the translation of the given Java code into equivalent Python:

```Python
class Enum16MsType:
    PDB_ID = 0x0007

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.count = reader.parse_unsigned_short_val()
        self.underlying_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 16)
        self.field_descriptor_list_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 16)
        self.property = MsProperty(reader)
        self.name = reader.parse_string(pdb, 'StringSt')
        reader.skip_padding()

    def get_pdb_id(self):
        return self.PDB_ID

class AbstractPdb:
    pass

class PdbByteReader:
    def parse_unsigned_short_val(self):
        # implementation
        pass

    def parse_string(self, pdb, string_type):
        # implementation
        pass

    def skip_padding(self):
        # implementation
        pass

class RecordNumber:
    @staticmethod
    def parse(pdb, reader, record_category, size):
        # implementation
        pass

class MsProperty:
    def __init__(self, reader):
        self.reader = reader

# Example usage:

pdb = AbstractPdb()
reader = PdbByteReader()

enum_type = Enum16MsType(pdb, reader)
print(enum_type.get_pdb_id())
```

Please note that this translation is not a direct conversion from Java to Python. It's more of an equivalent implementation in Python. The actual code may vary depending on the specific requirements and constraints of your project.

Also, some parts like `AbstractPdb`, `PdbByteReader`, `RecordNumber` and `MsProperty` are just placeholders for classes that you would need to implement according to their respective Java counterparts.