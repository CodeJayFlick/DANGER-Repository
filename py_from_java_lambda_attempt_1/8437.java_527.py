Here is the translation of the given Java code into equivalent Python:

```Python
class IndirectVirtualBaseClass16MsType:
    PDB_ID = 0x0402

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.direct_virtual_base_class_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 16)
        self.virtual_base_pointer_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 16)
        self.attribute = ClassFieldMsAttributes(reader).get_attributes()
        
        numeric = Numeric(reader)
        if not numeric.is_integral():
            raise PdbException("Expecting integral numeric")
        self.virtual_base_pointer_offset_from_address_point = numeric.get_integral()

        numeric = Numeric(reader)
        if not numeric.is_integral():
            raise PdbException("Expecting integral numeric")
        self.virtual_base_offset_from_vb_table = numeric.get_integral()


    def get_pdb_id(self):
        return self.PDB_ID


class RecordNumber:
    @staticmethod
    def parse(pdb, reader, category, size):
        # implement the parsing logic here
        pass


class ClassFieldMsAttributes:
    def __init__(self, reader):
        # implement the attribute retrieval logic here
        pass

    def get_attributes(self):
        return None  # or any other default value


class Numeric:
    @staticmethod
    def is_integral():
        # implement the integral check logic here
        return False

    def get_integral(self):
        raise PdbException("Not implemented yet")


class PdbException(Exception):
    pass
```

Please note that this translation assumes a basic understanding of Python and Java. The actual implementation details, such as parsing logic for `RecordNumber`, attribute retrieval logic for `ClassFieldMsAttributes`, integral check logic for `Numeric` class, are left out in the above code snippet.