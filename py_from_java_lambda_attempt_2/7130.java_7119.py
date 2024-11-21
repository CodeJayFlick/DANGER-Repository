Here is the translation of the given Java code into equivalent Python:

```Python
class FieldIDItem:
    def __init__(self):
        self.class_index = None
        self.type_index = None
        self.name_index = None

    @classmethod
    def from_reader(cls, reader):
        try:
            self.class_index = reader.read_short()
            self.type_index = reader.read_short()
            self.name_index = reader.read_int()
        except Exception as e:
            print(f"Error: {e}")

    def get_class_index(self):
        return self.class_index

    def get_type_index(self):
        return self.type_index

    def get_name_index(self):
        return self.name_index
```

Please note that Python does not have direct equivalent of Java's `BinaryReader` and `StructConverter`. In the above code, I used a class method to read data from some reader object. The actual implementation would depend on how you plan to use this class.

Also, there is no direct equivalent of Java's `DataType` in Python. If you want to represent similar concept in Python, you can create your own custom class or use existing classes like `dict`, `list`, etc., depending on the context and requirements.