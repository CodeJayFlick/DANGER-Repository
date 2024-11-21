Here is the translation of the given Java code into Python:

```Python
class AbstractDefaultArgumentsMsType:
    def __init__(self, pdb, reader, record_number_size, str_type):
        super().__init__()
        self.type_record_number = RecordNumber.parse(pdb, reader, 'TYPE', record_number_size)
        self.expression = reader.parse_string(pdb, str_type)

    def emit(self, builder, bind):
        builder.append(pdb.get_type_record(self.type_record_number))
        builder.append("  ")
        builder.append(self.expression)


class PdbByteReader:
    @staticmethod
    def parse_string(pdb, str_type):
        # This method is not implemented in the given Java code.
        pass


class RecordNumber:
    @classmethod
    def parse(cls, pdb, reader, record_category, size):
        # This method is not implemented in the given Java code.
        pass


class AbstractPdb:
    def get_type_record(self, type_number):
        # This method is not implemented in the given Java code.
        pass

```

Please note that this translation assumes that `RecordNumber`, `AbstractPdb` and other classes are defined elsewhere.