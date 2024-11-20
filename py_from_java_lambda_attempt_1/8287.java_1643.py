Here is the translation of the given Java code into Python:

```Python
class RegisterRelativeAddress3216MsSymbol:
    PDB_ID = 0x020c

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.offset = reader.parse_var_sized_offset(32)
        self.register_index = reader.parse_unsigned_short_val()
        self.type_record_number = RecordNumber().parse(pdb, reader, 'TYPE', 16)
        self.name = reader.parse_string(pdb, StringParseType.STRING_UTF8_ST)
        reader.align4()
        self.register_name = RegisterName(pdb, self.register_index)

    def get_pdb_id(self):
        return self.PDB_ID

    def get_symbol_type_name(self):
        return "REGREL32_16"


class RecordNumber:
    @staticmethod
    def parse(pdb, reader, category, size):
        # Implement the logic to parse a record number here


class RegisterName:
    def __init__(self, pdb, register_index):
        self.pdb = pdb
        self.register_index = register_index

# Define other classes and functions as needed for PdbByteReader, StringParseType etc.
```

Please note that this is not a direct translation. Python does not have exact equivalents of Java's `package`, `public class`, `throws` keywords or the concept of static methods in the same way. The above code represents the equivalent logic and structure in Python.