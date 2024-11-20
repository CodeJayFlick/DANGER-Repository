Here is the equivalent Python code:

```Python
class DyldCacheImageTextInfo:
    def __init__(self):
        self.uuid = None
        self.load_address = 0
        self.text_segment_size = 0
        self.path_offset = 0
        self.path = ""

    @property
    def path(self):
        return self.path

    def from_binary_reader(reader):
        try:
            self.uuid = reader.read_bytes(16)
            self.load_address = int.from_bytes(reader.read_bytes(8), 'little')
            self.text_segment_size = int.from_bytes(reader.read_bytes(4), 'little')
            self.path_offset = int.from_bytes(reader.read_bytes(4), 'little')

            path_length = self.path_offset
            self.path = reader.read_string(path_length)
        except Exception as e:
            print(f"Error: {e}")

    def to_data_type(self):
        try:
            struct = {
                "uuid": {"type": "bytes", "length": 16},
                "load_address": {"type": "int64"},
                "text_segment_size": {"type": "int32"},
                "path_offset": {"type": "int32"}
            }

            return struct
        except Exception as e:
            print(f"Error: {e}")
```

Please note that Python does not have direct equivalent of Java's `StructConverter` and `BinaryReader`. This code is a simple translation of the provided Java code to Python.