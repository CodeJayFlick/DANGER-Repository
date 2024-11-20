class AbstractBaseClassMsType:
    def __init__(self, pdb=None, base_class_record_number=None, offset=0, attribute=None):
        self.pdb = pdb
        self.base_class_record_number = base_class_record_number
        self.offset = offset
        self.attribute = attribute

    @property
    def get_offset(self):
        return self.offset

    @property
    def get_attributes(self):
        return self.attribute

    @property
    def get_base_class_record_number(self):
        return self.base_class_record_number

    def emit(self, builder: str, bind=None) -> None:
        if attribute is not None:
            attribute.emit(builder)
        builder += f":{self.pdb.get_type_record(self.base_class_record_number)}"
        builder += "<@" + str(self.offset) + ">"

# Example usage
class PdbByteReader:
    def get_type_record(self, record_number):
        return "Type Record: {}".format(record_number)

class ClassFieldMsAttributes:
    def emit(self, builder: str) -> None:
        # Implementation of this method is missing in the original Java code.
        pass

pdb = PdbByteReader()
attribute = ClassFieldMsAttributes()

ms_type = AbstractBaseClassMsType(pdb=pdb, base_class_record_number=1, offset=2, attribute=attribute)
builder = "Builder"
ms_type.emit(builder)  # Output: Builder:<@2>:Type Record: 1
