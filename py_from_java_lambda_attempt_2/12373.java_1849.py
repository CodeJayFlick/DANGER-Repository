Here is the translation of the Java code to Python:
```
class QWordDataType:
    def __init__(self):
        self.description = "Unsigned Quad-Word (dq, 8-bytes)"
        self.length = 8
        self.assembly_mnemonic = "dq"

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, value):
        self._description = value

    @property
    def length(self):
        return self._length

    @length.setter
    def length(self, value):
        self._length = value

    @property
    def assembly_mnemonic(self):
        return self._assembly_mnemonic

    @assembly_mnemonic.setter
    def assembly_mnemonic(self, value):
        self._assembly_mnemonic = value

    def get_opposite_signedness_data_type(self):
        return SignedQWordDataType()

    def clone(self):
        return QWordDataType()
```
Note that I did not include the `SignedQWordDataType` class in this translation, as it was not provided. You would need to define a separate Python class for this.

Also, I used Python's property decorator to create read-only properties for the description, length, and assembly mnemonic attributes. This is equivalent to Java's getter/setter methods.