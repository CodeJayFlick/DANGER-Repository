Here is the translation of the given Java code into Python:

```Python
class VirtualBaseClass16MsType:
    PDB_ID = 0x0401

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
        # Implement the parsing logic here
        pass


class ClassFieldMsAttributes:
    def __init__(self, reader):
        # Implement the attribute reading logic here
        pass

    def get_attributes(self):
        return []  # Return a list of attributes for now


class Numeric:
    @staticmethod
    def is_integral():
        # Implement the integral check logic here
        pass

    def get_integral(self):
        # Implement the integral value retrieval logic here
        pass


class PdbException(Exception):
    pass
```

Please note that this translation assumes you have implemented the `RecordNumber`, `ClassFieldMsAttributes` and `Numeric` classes in Python. The actual implementation of these classes would depend on your specific requirements and data structures used to represent the corresponding Java classes.