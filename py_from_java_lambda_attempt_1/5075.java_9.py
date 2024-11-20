Here is the translation of the given Java code into Python:

```Python
class DebugMisc:
    NAME = "IMAGE_DEBUG_MISC"
    IMAGE_DEBUG_MISC_EXENAME = 1

    def __init__(self):
        self.debug_dir = None
        self.data_type = None
        self.length = None
        self.unicode = False
        self.reserved = bytearray(3)
        self.actual_data = ""

    @classmethod
    def create_debug_misc(cls, reader, debug_dir, validator):
        misc = cls()
        misc.init_debug_misc(reader, debug_dir, validator)
        return misc

    def init_debug_misc(self, reader, debug_dir, validator):
        self.debug_dir = debug_dir
        old_index = reader.tell()
        index = debug_dir.get_pointer_to_raw_data() & 0xFFFFFFFF
        if not validator.check_pointer(index):
            print(f"Invalid file index {index}")
            return
        reader.seek(index)
        self.data_type = reader.read_int()
        self.length = reader.read_int()
        self.unicode = bool(reader.read_byte())
        self.reserved = bytearray(3)
        for i in range(3):
            self.reserved[i] = reader.read_byte()
        if self.length > 0:
            if self.unicode:
                self.actual_data = reader.read_unicode_string(self.length - 12).decode('utf-16le')
            else:
                self.actual_data = reader.read_ascii_string().encode('ascii').decode('utf-8')
        else:
            print(f"Bad string length {self.length}")
        reader.seek(old_index)

    def get_data_type(self):
        return self.data_type

    def get_length(self):
        return self.length

    def is_unicode(self):
        return self.unicode

    def get_reserved(self):
        return bytes(self.reserved)

    def get_actual_data(self):
        return self.actual_data

    def __str__(self):
        if self.get_data_type() == DebugMisc.IMAGE_DEBUG_MISC_EXENAME:
            return f"Misc Debug Information: {self.get_actual_data()}"
        else:
            return f"Unknown Misc Debug Information Type: {self.get_data_type()}"

    def get_debug_directory(self):
        return self.debug_dir

    @classmethod
    def to_data_type(cls, misc):
        struct = {}
        if "DataType" in struct and "Length" in struct and "Unicode" in struct:
            for key, value in struct.items():
                print(f"{key}: {value}")
```

This Python code defines a class `DebugMisc` that represents the IMAGE_DEBUG_MISC structure. It includes methods to create an instance of this class from binary data, read and write various fields within the structure, and convert it into a string representation.

Please note that in order for this code to work correctly with binary files, you would need additional functions or classes that can handle reading and writing bytes from these files.