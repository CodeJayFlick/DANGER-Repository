Here is the translation of the given Java code into Python:

```Python
class StaticMemberStMsType:
    PDB_ID = 0x1406

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)
        self.attribute = ClassFieldMsAttributes(reader)
        self.field_type_record_number = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32)
        self.name = reader.parse_string(pdb, StringParseType.StringSt)
        reader.align4()

    def get_pdb_id(self) -> int:
        return self.PDB_ID
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. In Python, everything is public by default.

Also note that the translation assumes that you are using a type hinting system like mypy or pytype to ensure that your code adheres to certain rules about types. Without such a system, Python does not have built-in support for static typing.