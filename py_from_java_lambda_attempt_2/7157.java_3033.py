Here is the translation of the given Java code into equivalent Python:

```Python
class FBPKPartition:
    def __init__(self):
        self.type = None
        self.name = None
        self.data_size = None
        self.unknown1 = None
        self.offset_to_next_partition_table = None
        self.unknown2 = None
        self.fbpt = None
        self.data_start_offset = None

    def read_from_binary_reader(self, reader):
        try:
            self.type = int.from_bytes(reader.read(4), 'little')
            self.name = reader.read_string(FBPKConstants.NAME_MAX_LENGTH)
            self.data_size = int.from_bytes(reader.read(4), 'little')
            self.unknown1 = int.from_bytes(reader.read(4), 'little')
            self.offset_to_next_partition_table = int.from_bytes(reader.read(4), 'little')
            self.unknown2 = int.from_bytes(reader.read(4), 'little')

            if self.type == FBPKConstants.PARTITION_TYPE_DIRECTORY:
                self.fbpt = FBPT(reader)
            elif self.type == FBPKConstants.PARTITION_TYPE_FILE:
                self.data_start_offset = reader.get_pointer_index()
        except Exception as e:
            print(f"Error reading from binary reader: {e}")

    def get_type(self):
        return self.type

    def get_name(self):
        return self.name

    def get_fbpt(self):
        return self.fbpt

    def get_data_start_offset(self):
        return self.data_start_offset

    def get_data_size(self):
        return self.data_size

    def get_offset_to_next_partition_table(self):
        return self.offset_to_next_partition_table

    def is_directory(self):
        return self.type == FBPKConstants.PARTITION_TYPE_DIRECTORY

    def is_file(self):
        return self.type == FBPKConstants.PARTITION_TYPE_FILE

    def get_unknown1(self):
        return self.unknown1

    def get_unknown2(self):
        return self.unknown2
```

Note that this translation assumes the existence of `FBPT` and `FBPKConstants` classes, which are not provided in your original code. You would need to implement these separately based on their definitions.

Also note that Python does not have direct equivalents for Java's `BinaryReader`, `IOException`, or `StructConverter`. The equivalent functionality is implemented using the built-in file handling functions and error handling mechanisms of Python.