Here is the translation of the given Java code into equivalent Python:

```Python
class ConstantPoolInvokeDynamicInfo:
    def __init__(self):
        self.bootstrap_method_attr_index = None
        self.name_and_type_index = None

    @classmethod
    def from_reader(cls, reader):
        instance = cls()
        super().__init__()
        try:
            instance.bootstrap_method_attr_index = reader.read_next_short()
            instance.name_and_type_index = reader.read_next_short()
        except Exception as e:
            print(f"Error: {e}")
        return instance

    @property
    def bootstrap_method_attr_index(self):
        return self.bootstrap_method_attr_index & 0xffff

    @property
    def name_and_type_index(self):
        return self.name_and_type_index & 0xffff

    def to_data_type(self, reader=None):
        if reader is None:
            raise Exception("Reader not provided")
        
        data_type = {"name": "CONSTANT_InvokeDynamic_info", 
                     "structure": [
                         {"type": "byte", "field_name": "tag"},
                         {"type": "short", "field_name": "bootstrap_method_attr_index"},
                         {"type": "short", "field_name": "name_and_type_index"}
                     ]
                    }
        return data_type
```

Note that Python does not have direct equivalent of Java's `BinaryReader` and `IOException`. The provided code assumes the reader is already available.