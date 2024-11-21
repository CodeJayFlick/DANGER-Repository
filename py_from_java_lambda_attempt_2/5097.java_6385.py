Here is the translation of the Java code into Python:

```Python
class S_DATAREF:
    def __init__(self):
        self.checksum = None

    @classmethod
    def create_s_dataref(cls, length: int, type: int, reader, ptr) -> 'S_DATAREF':
        s_dataref = cls()
        s_dataref.init_s_dataref(length, type, reader, ptr)
        return s_dataref

    def init_s_dataref(self, length: int, type: int, reader, ptr):
        self.process_debug_symbol(length, type)

        if type != 0x0001:
            raise ValueError("Incorrect type!")

        self.checksum = reader.read_int(ptr); ptr += 4
        self.offset = reader.read_int(ptr); ptr += 4
        self.section = reader.read_short(ptr); ptr += 2

    def get_checksum(self):
        return self.checksum


class BinaryReader:
    SIZEOF_INT = 4
    SIZEOF_SHORT = 2

    def read_int(self, ptr: int) -> int:
        # implement your own binary reading logic here
        pass

    def read_short(self, ptr: int) -> int:
        # implement your own binary reading logic here
        pass


def process_debug_symbol(length: int, type: int):
    # implement your own debug symbol processing logic here
    pass
```

Please note that the `BinaryReader` class and the `process_debug_symbol` function are not fully implemented in this translation. You would need to add the actual implementation for these methods based on how you want to handle binary reading and debugging symbols in Python.