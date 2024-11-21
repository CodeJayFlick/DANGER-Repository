Here is the translation of the given Java code into Python:

```Python
class AbstractEnumMsType:
    def __init__(self):
        self.TYPE_STRING = "enum"
        self.underlying_record_number = None
        super().__init__()

    def __init__(self, pdb, reader=None):
        if reader is not None:
            super(pdb, reader)
        else:
            super()

    @classmethod
    def from_pdb(cls, pdb, name, underlying_record_number, field_descriptor_list_record_number, property, num_elements):
        instance = cls()
        instance.name = name
        instance.underlying_record_number = underlying_record_number
        instance.field_descriptor_list_record_number = field_descriptor_list_record_number
        instance.property = property
        instance.count = num_elements
        return instance

    def get_underlying_record_number(self):
        return self.underlying_record_number

    def emit(self, builder, bind):
        my_builder = StringBuilder()
        my_builder.append(self.TYPE_STRING)
        my_builder.append(" ")
        my_builder.append(self.name)
        if self.count != -1:
            my_builder.append(str(self.count))
            my_builder.append(",")
        my_builder.append(pdb.get_type_record(self.underlying_record_number))
        my_builder.append(",")
        my_builder.append(self.property)
        my_builder.append(">")

    def get_type_string(self):
        return self.TYPE_STRING
```

Note: This Python code does not include the `AbstractPdb`, `RecordNumber`, and other classes that are present in the original Java code. It only includes the translation of the given class, assuming those classes exist or can be implemented similarly in Python.