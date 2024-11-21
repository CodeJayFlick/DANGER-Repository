Here is the translation of the Java code into equivalent Python:

```Python
class ConstantPoolNameAndTypeInfo:
    def __init__(self):
        self.name_index = None
        self.descriptor_index = None

    def read_from_binary_reader(self, reader):
        try:
            super().__init__()
            self.name_index = reader.read_next_short()
            self.descriptor_index = reader.read_next_short()
        except Exception as e:
            print(f"Error reading from binary reader: {e}")

    @property
    def name_index(self):
        return self.name_index & 0xffff

    @property
    def descriptor_index(self):
        return self.descriptor_index & 0xffff

    def to_data_type(self) -> dict:
        data_type = {
            "name": "CONSTANT_ NameAndType_info",
            "structure": [
                {"type": "byte", "field_name": "tag"},
                {"type": "word", "field_name": "name_index"},
                {"type": "word", "field_name": "descriptor_index"}
            ]
        }
        return data_type
```

Note that Python does not have direct equivalents for Java's `public`, `private`, and other access modifiers. In this translation, I've used the same naming conventions as in the original code to indicate public methods and variables.

Also note that Python does not require explicit type declarations like Java does. The types of variables are inferred by the interpreter at runtime.