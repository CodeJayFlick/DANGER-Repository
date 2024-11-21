class AbstractOneMethodMsType:
    def __init__(self, pdb, reader, record_number_size, str_type):
        super().__init__()
        self.attribute = ClassFieldMsAttributes(reader)
        self.procedure_type_record_number = RecordNumber.parse(pdb, reader, 'TYPE', record_number_size)
        if (self.attribute.get_property() in [ClassFieldMsAttributes.Property.INTRO, 
                                               ClassFieldMsAttributes.Property.INTRO_PURE]):
            self.offset_in_vf_table_if_intro_virtual = reader.parse_unsigned_int_val()
        else:
            self.offset_in_vf_table_if_intro_virtual = 0
        self.name = reader.parse_string(pdb, str_type)
        reader.skip_padding()

    def emit(self, builder, bind):
        # No API for this. Just outputting something that might be useful.
        # At this time, not doing anything with bind here; don't think it is warranted.
        builder.append("<")
        builder.append(str(self.attribute))
        builder.append(": ")
        builder.append(pdb.get_type_record(self.procedure_type_record_number))
        builder.append(",")
        builder.append(str(self.offset_in_vf_table_if_intro_virtual))
        builder.append(">")

class ClassFieldMsAttributes:
    def __init__(self, reader):
        pass

    @property
    def get_property(self):
        return None  # Replace with actual implementation

class RecordNumber:
    @classmethod
    def parse(cls, pdb, reader, record_category, size):
        pass

    @staticmethod
    def get_type_record(record_number):
        pass

class PdbByteReader:
    def parse_unsigned_int_val(self):
        pass

    def parse_string(self, pdb, str_type):
        pass

    def skip_padding(self):
        pass

# Example usage:

pdb = None  # Replace with actual implementation
reader = PdbByteReader()  # Replace with actual implementation
record_number_size = 0  # Replace with actual value
str_type = None  # Replace with actual implementation

one_method_ms_type = AbstractOneMethodMsType(pdb, reader, record_number_size, str_type)
builder = StringBuilder()
bind = None  # Replace with actual implementation

one_method_ms_type.emit(builder, bind)

print(builder.toString())
