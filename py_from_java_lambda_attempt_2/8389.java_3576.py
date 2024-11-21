Here is the translation of the given Java code into equivalent Python:

```Python
class Bitfield16MsType:
    PDB_ID = 0x0206

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.length = reader.parse_unsigned_byte_val()
        self.position = reader.parse_unsigned_byte_val()
        self.element_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 16)
        reader.skip_padding()

    def get_pdb_id(self):
        return self.PDB_ID

class AbstractPdb:
    pass

class PdbByteReader:
    def parse_unsigned_byte_val(self):
        # implement this method
        pass

    def skip_padding(self):
        # implement this method
        pass

class RecordNumber:
    @staticmethod
    def parse(pdb, reader, category, size):
        # implement this method
        pass

# Usage example:

pdb = AbstractPdb()
reader = PdbByteReader()

bitfield16_ms_type = Bitfield16MsType(pdb, reader)
print(bitfield16_ms_type.get_pdb_id())
```

Please note that the above Python code is not a direct translation of Java code. It's more like an equivalent implementation in Python. The actual functionality might be different due to differences between languages and their standard libraries.

In this example:

- `AbstractPdb` and `PdbByteReader` are just placeholders for classes you would need to implement.
- `RecordNumber.parse()` is also a placeholder method that needs to be implemented according to your specific requirements.