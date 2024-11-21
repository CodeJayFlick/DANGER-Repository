Here is the translation of the given Java code into equivalent Python:

```Python
class VirtualBaseClassMsType:
    PDB_ID = 0x1401

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.attribute = ClassFieldMsAttributes(reader)
        self.direct_virtual_base_class_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)
        self.virtual_base_pointer_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)

    def get_pdb_id(self):
        return self.PDB_ID

class ClassFieldMsAttributes:
    pass

class RecordNumber:
    @staticmethod
    def parse(pdb, reader, category, size):
        # implement this method as needed
        pass

class Numeric:
    def __init__(self, reader):
        self.reader = reader

    def is_integral(self):
        return True  # or False if not integral

    def get_integral(self):
        return 0  # replace with actual value


# Example usage:

pdb = 'your_pdb_data'
reader = PdbByteReader(pdb)  # implement this class as needed
virtual_base_class_ms_type = VirtualBaseClassMsType(pdb, reader)
print(virtual_base_class_ms_type.get_pdb_id())
```

Please note that the `PdbByteReader`, `RecordNumber`, and `Numeric` classes are not implemented in this translation. You would need to implement these classes based on your specific requirements.