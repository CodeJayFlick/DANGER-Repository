Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractOverloadedMethodMsType:
    def __init__(self, pdb, reader, record_number_size, str_type):
        self.count = reader.parse_unsigned_short_val()
        self.method_list_record_number = RecordNumber.parse(pdb, reader, 'TYPE', record_number_size)
        self.name = reader.parse_string(pdb, str_type)

class PdbByteReader:
    def parse_unsigned_short_val(self):
        # implementation of this method
        pass

    def parse_string(self, pdb, str_type):
        # implementation of this method
        pass

class RecordNumber:
    @staticmethod
    def parse(pdb, reader, category, record_number_size):
        # implementation of this method
        pass

class AbstractPdb:
    def get_type_record(self, record_number):
        # implementation of this method
        pass


def emit(builder, bind, ms_type: 'AbstractOverloadedMethodMsType'):
    builder.append("overloaded[")
    builder.append(str(ms_type.count))
    builder.append("]:")
    builder.append(ms_type.name)
    builder.append(ms_type.pdb.get_type_record(ms_type.method_list_record_number))

# Example usage:
pdb = AbstractPdb()
reader = PdbByteReader()
record_number_size = 10
str_type = 'some_string_type'
ms_type = AbstractOverloadedMethodMsType(pdb, reader, record_number_size, str_type)
builder = StringBuilder()
emit(builder, None, ms_type)