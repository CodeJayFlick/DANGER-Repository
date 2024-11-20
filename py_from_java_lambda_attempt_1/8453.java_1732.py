Here is the translation of the given Java code into equivalent Python:

```Python
class MemberStMsType:
    PDB_ID = 0x1405

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)
        self.attribute = ClassFieldMsAttributes(reader)
        self.field_type_record_number = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32)
        numeric = Numeric(reader)
        if not numeric.is_integral():
            raise PdbException("Expecting integral numeric")
        self.offset = numeric.get_integral()
        self.name = reader.parse_string(pdb, StringParseType.StringSt)
        reader.align4()

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractPdb:
    pass


class PdbByteReader:
    def parse_string(self, pdb: 'AbstractPdb', string_parse_type: str):
        raise NotImplementedError

    def align4(self):
        raise NotImplementedError


class ClassFieldMsAttributes:
    def __init__(self, reader: 'PdbByteReader'):
        self.reader = reader


class RecordNumber:
    @staticmethod
    def parse(pdb: 'AbstractPdb', reader: 'PdbByteReader', record_category: str, size):
        raise NotImplementedError


class Numeric:
    def is_integral(self) -> bool:
        return False

    def get_integral(self) -> int:
        raise NotImplementedError


class PdbException(Exception):
    pass
```

Please note that Python does not support direct translation of Java code into equivalent Python. This code has been written from scratch in Python, following the same logic and structure as the original Java code.