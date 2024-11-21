Here is a translation of the Java code into equivalent Python:

```Python
class ByteDataType:
    def __init__(self):
        self.description = "Unsigned Byte (db)"
        self.length = 1
        self.assembly_mnemonic = "db"

    def get_description(self):
        return self.description

    def get_length(self):
        return self.length

    def get_assembly_mnemonic(self):
        return self.assembly_mnemonic

    def get_decompiler_display_name(self, language):
        if language == 'java':
            return 'ubyte'
        else:
            return self.name

    def get_opposite_signedness_data_type(self):
        return SignedByteDataType()

class SignedByteDataType:
    @classmethod
    def data_type(cls):
        return cls().clone()

    def clone(self, dtm):
        if dtm == self.get_dtm():
            return self
        else:
            return ByteDataType(dtm)

# Statically defined ByteDataType instance.
byte_data_type = ByteDataType()
```

Please note that Python does not have a direct equivalent to Java's static keyword. Instead, we create an instance of the class and assign it to a variable.

Also, Python doesn't support method overriding like Java does with its @Override annotation.