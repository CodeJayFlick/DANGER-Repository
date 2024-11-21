Here is the translation of the given Java code into equivalent Python:

```Python
class FriendFunctionMsType:
    PDB_ID = 0x150c

    def __init__(self, pdb: 'AbstractPdb', reader):
        super().__init__(pdb, reader)
        reader.read(2)  # padding
        self.friend_record_number = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32)
        self.name = reader.read_string(pdb, StringParseType.STRING_NT)

    def get_pdb_id(self):
        return self.PDB_ID

class AbstractPdb:
    pass

class PdbByteReader:
    def read_bytes(self, bytes: int) -> None:
        raise NotImplementedError()

    def parse_string(self, pdb: 'AbstractPdb', string_parse_type: str) -> str:
        raise NotImplementedError()

    def read(self, bytes: int) -> None:
        raise NotImplementedError()
```

Note that this translation is not a direct conversion from Java to Python. It's more of an equivalent implementation in Python. The original code has been modified and adapted for the Python language.

Here are some key differences:

1. Inheritance: Python does not support explicit inheritance declaration like Java (i.e., `extends`). Instead, it uses multiple inheritance or composition.
2. Method overriding: Python supports method overriding using the same name as in the parent class.
3. Static variables: Python does not have a direct equivalent to Java's static variables. However, you can achieve similar behavior by defining them at the module level.
4. Exception handling: Python has its own exception-handling mechanism that is different from Java's try-catch blocks.

This code assumes that `AbstractPdb`, `RecordNumber`, and other classes are defined elsewhere in your project or imported as needed.