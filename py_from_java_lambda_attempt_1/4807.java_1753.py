Here is the equivalent Python code:

```Python
class DyldCacheAcceleratorDof:
    def __init__(self):
        self.section_address = None
        self.section_size = None
        self.image_index = None

    @staticmethod
    def from_binary_reader(reader):
        try:
            section_address = reader.read_long()
            section_size = reader.read_int()
            image_index = reader.read_int()
            return DyldCacheAcceleratorDof(section_address, section_size, image_index)
        except Exception as e:
            raise IOError("Error reading DYLD accelerator DOF") from e

    def to_data_type(self):
        struct = {"sectionAddress": self.section_address,
                  "sectionSize": self.section_size,
                  "imageIndex": self.image_index}
        return struct
```

Note that Python does not have direct equivalents for Java's `StructConverter` and `DataType`, so I've replaced them with a simple class. The `from_binary_reader` method is used to create an instance of the class from binary data, and the `to_data_type` method returns a dictionary representing the structure as if it were a Python dictionary.

Also note that in Python, we don't need to specify types for variables or function parameters like Java does with `long`, `int`, etc.