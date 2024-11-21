Here is the translation of the given Java code into Python:

```Python
class Structure19MsType:
    PDB_ID = 0x1609

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.property = MsProperty(reader)
        x = reader.parse_unsigned_short_val()  # unknown
        self.field_descriptor_list_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)
        self.derived_from_list_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)
        self.v_shape_table_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)

        # TODO: has more... guessing below... commented out some other conditions, but we
        # might want to investigate if any data hits them.
        numeric_unknown = Numeric(reader)  # unknown. Might even be just a short.
        numeric = Numeric(reader)
        if not numeric.is_integral():
            raise PdbException("Expecting integral numeric")
        self.size = numeric.get_integral()
        if reader.has_more_non_pad():
            self.name = reader.parse_string(pdb, 'StringNt')
            if reader.has_more_non_pad():
                self.mangled_name = reader.parse_string(pdb, 'StringNt')

    def get_pdb_id(self):
        return PDB_ID

class MsProperty:
    pass  # This class is not implemented in the given Java code.

class RecordNumber:
    @staticmethod
    def parse(pdb, reader, category, size):
        pass  # This method is not implemented in the given Java code.

class Numeric:
    def __init__(self, reader):
        self.reader = reader

    def get_integral(self):
        return self.reader.parse_unsigned_short_val()  # unknown. Might even be just a short.
```

Please note that this translation does not include all classes and methods from the original Java code as they are not implemented in the given code snippet.