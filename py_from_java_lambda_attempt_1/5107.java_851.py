Here is the translation of the Java code into Python:

```Python
class UnknownSymbol:
    def __init__(self):
        pass

    @classmethod
    def create_unknown_symbol(cls, length: int, type: str, reader, ptr) -> 'UnknownSymbol':
        unknown_symbol = cls()
        unknown_symbol.init_unknown_symbol(length, type, reader, ptr)
        return unknown_symbol

    def init_unknown_symbol(self, length: int, type: str, reader, ptr):
        self.process_debug_symbol(length, type)
        try:
            self.unknown = reader.read_byte_array(ptr, length)
        except Exception as e:
            print(f"Unexpected exception: {e}")

    @classmethod
    def process_debug_symbol(cls, length: int, type: str):
        pass

    def get_unknown(self) -> bytes:
        return self.unknown


class FactoryBundledWithBinaryReader:
    def read_byte_array(self, ptr: int, length: int) -> bytes:
        # implement this method
        pass


def main():
    reader = FactoryBundledWithBinaryReader()
    unknown_symbol = UnknownSymbol.create_unknown_symbol(10, "type", reader, 100)
    print(unknown_symbol.get_unknown())


if __name__ == "__main__":
    main()

```

Note that the `FactoryBundledWithBinaryReader` class is not fully implemented in this translation. You would need to implement its methods based on your specific requirements.