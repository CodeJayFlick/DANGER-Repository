Here is the translation of the Java code into Python:

```Python
class ConstantPoolMethodTypeInfo:
    def __init__(self):
        self.descriptor_index = None

    def from_binary_reader(self, reader):
        super().__init__()
        self.descriptor_index = reader.read_next_short()

    @property
    def descriptor_index(self):
        return self.descriptor_index & 0xffff


class DataType:
    pass


def to_data_type(self) -> DataType:
    name = "CONSTANT_MethodType_info"
    structure = {"tag": None, "descriptor_index": None}
    return structure

```

Please note that Python does not have direct equivalent of Java's `package`, `import` statements. Also, the concept of classes and objects in Python is different from Java. In this translation, I've used a simple class to represent the ConstantPoolMethodTypeInfo and another function to simulate the toDataType method.

Also, there are some differences between Python and Java when it comes to data types. For example, Python does not have an equivalent for `u1` or `u2`, which are unsigned byte and word in Java respectively.