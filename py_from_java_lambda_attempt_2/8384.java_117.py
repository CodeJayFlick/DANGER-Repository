Here is the translation of the given Java code into Python:

```Python
class BaseClass16MsType:
    PDB_ID = 0x0400

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.base_class_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 16)
        self.attribute = ClassFieldMsAttributes(reader)
        numeric = Numeric(reader)
        if not numeric.is_integral():
            raise PdbException("Expecting integral numeric")
        self.offset = numeric.get_integral()
        reader.skip_padding()

    def get_pdb_id(self):
        return self.PDB_ID

class RecordNumber:
    @staticmethod
    def parse(pdb, reader, category, size):
        # implement the logic to parse record number here
        pass

class ClassFieldMsAttributes:
    def __init__(self, reader):
        # implement the logic for class field ms attributes here
        pass

class Numeric:
    def is_integral(self):
        # implement the logic to check if numeric value is integral here
        return False

    def get_integral(self):
        # implement the logic to get integral value from numeric here
        return 0

class PdbException(Exception):
    pass
```

Please note that this translation assumes you have a basic understanding of Python and its syntax. Also, some parts like `RecordNumber.parse`, `ClassFieldMsAttributes` and `Numeric.is_integral()` are not implemented as they were in the original Java code. You would need to implement these based on your specific requirements.