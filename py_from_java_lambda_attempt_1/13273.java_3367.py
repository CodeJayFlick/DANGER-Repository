Here is the translation of the given Java code into equivalent Python:

```Python
class ConstantPoolLongInfo:
    def __init__(self):
        self.high_bytes = None
        self.low_bytes = None

    def from_binary_reader(self, reader):
        super().__init__()
        self.high_bytes = int.from_bytes(reader.read(4), 'big')
        self.low_bytes = int.from_bytes(reader.read(4), 'big')

    @property
    def value(self):
        return (self.high_bytes << 32) + self.low_bytes

    def __str__(self):
        return str(self.value)

    def to_data_type(self, name='CONSTANT_Long_info'):
        structure = {'tag': ('B', None), 'high_bytes': ('I', None), 'low_bytes': ('I', None)}
        return structure
```

Note that Python does not have direct equivalents for Java's `BinaryReader` and `StructureDataType`. The equivalent functionality has been implemented using built-in Python functions.