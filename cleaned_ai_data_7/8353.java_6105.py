class AbstractMemberModifyMsType:
    def __init__(self, pdb, reader, str_type):
        super().__init__()
        self.attribute = ClassFieldMsAttributes(reader)
        self.base_class_definition_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)
        self.name = reader.parse_string(pdb, str_type)
        reader.align4()

    def emit(self, builder, bind):
        # No API for this. Just outputting something that might be useful.
        # At this time, not doing anything with bind here; don't think it is warranted.
        builder.append(str(self.attribute))
        builder.append(": ")
        builder.append(pdb.get_type_record(self.base_class_definition_record_number))
        builder.append(" ")
        builder.append(self.name)

class ClassFieldMsAttributes:
    def __init__(self, reader):
        pass

class RecordNumber:
    @staticmethod
    def parse(pdb, reader, category, size):
        return None  # This method is not implemented in the given Java code.

class PdbByteReader:
    def parse_string(self, pdb, str_type):
        return ""  # This method is not implemented in the given Java code.
    
    def align4(self):
        pass

class AbstractPdb:
    @staticmethod
    def get_type_record(record_number):
        return None  # This method is not implemented in the given Java code.

# Example usage:

pdb = None  # Replace with your PDB instance
reader = PdbByteReader()  # Replace with your reader instance
str_type = "your_string_type"  # Replace with your string type

ms_type = AbstractMemberModifyMsType(pdb, reader, str_type)
builder = StringBuilder()
bind = None  # This is not used in the given Java code.
ms_type.emit(builder, bind)

print(builder.toString())
