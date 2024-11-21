Here is the translation of the Java code to Python:
```python
class SGData32New(DebugSymbol):
    @classmethod
    def create(cls, length: int, type: int, reader: 'FactoryBundledWithBinaryReader', ptr: int) -> 'SGData32New':
        s_gdata32_new = cls(reader.get_factory().create(cls))
        s_gdata32_new.init(length, type, reader, ptr)
        return s_gdata32_new

    def __init__(self):
        pass  # DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.

    def init(self, length: int, type: int, reader: 'FactoryBundledWithBinaryReader', ptr: int) -> None:
        self.process_debug_symbol(length, type)

        unknown = reader.read_int(ptr)
        ptr += 4
        self.offset = reader.read_int(ptr)
        ptr += 4
        self.section = reader.read_short(ptr)
        ptr += 2

        name_len = reader.read_byte(ptr)
        ptr += 1

        self.name = reader.read_ascii_string(ptr, Conv.byte_to_int(name_len))

        print(f"S_ DATA32_NEW: {unknown}")

class FactoryBundledWithBinaryReader:
    def get_factory(self):
        # implementation missing
        pass

    def read_int(self, ptr: int) -> int:
        # implementation missing
        pass

    def read_ascii_string(self, ptr: int, length: int) -> str:
        # implementation missing
        pass

class Conv:
    @staticmethod
    def byte_to_int(byte: int) -> int:
        return byte  # assuming the conversion is simple and doesn't require any actual logic
```
Note that I had to make some assumptions about the `FactoryBundledWithBinaryReader` class, as its implementation was missing in the original Java code. Similarly, I assumed a simple conversion from bytes to integers for the `Conv.byte_to_int()` method.

Also, please note that this is just one possible translation of the Java code to Python, and there may be other ways to achieve the same result.