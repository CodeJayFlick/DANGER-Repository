Here is a translation of the Java code into equivalent Python:

```Python
class SignedByteDataType:
    def __init__(self):
        self.name = "sbyte"
        self.description = "Signed Byte (sdb)"
        self.length = 1
        self.assembly_mnemonic = "sdb"

    def get_description(self):
        return self.description

    def get_length(self):
        return self.length

    def get_assembly_mnemonic(self):
        return self.assembly_mnemonic

    def get_decompiler_display_name(self, language):
        if language == "java":
            return "byte"
        else:
            return self.name

    def get_opposite_signedness_data_type(self):
        return SignedByteDataType()

    @classmethod
    def clone(cls, dtm):
        if dtm is not None and dtm == cls().get_datatype_manager():
            return cls()
        else:
            return SignedByteDataType(dtm)

    @classmethod
    def get_c_type_declaration(cls, data_organization=False):
        return "int8_t"

SignedByteDataType.data_type = SignedByteDataType()

class ByteDataType(SignedByteDataType):
    pass

ByteDataType.data_type = SignedByteDataType()
```

Please note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. Also, the concept of static variables is different in Python as it uses class attributes instead.