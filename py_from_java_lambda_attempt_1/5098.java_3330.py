Here is the translation of the Java code to Python:
```
class S_END:
    def __init__(self):
        pass

    @classmethod
    def create_s_end(cls, length: int, type: int, reader, ptr: int) -> 'S_END':
        s_end = cls(reader.get_factory().create(cls))
        s_end.init_s_end(length, type, reader, ptr)
        return s_end

    def init_s_end(self, length: int, type: int, reader, ptr: int):
        self.process_debug_symbol(length, type)
        print(f"{reader.get_pointer_index()} -- {ptr}")
        self.name = "END"
        self.offset = 0
        self.section = 0

def process_debug_symbol(length: int, type: int) -> None:
    pass  # implement this method in Python equivalent of Java's DebugSymbol class

class FactoryBundledWithBinaryReader:
    def get_factory(self):
        raise NotImplementedError("Must be implemented")

    def get_pointer_index(self) -> int:
        raise NotImplementedError("Must be implemented")
```
Note that I had to make some assumptions about the `FactoryBundledWithBinaryReader` and `DebugSymbol` classes, as they are not defined in the original Java code. In Python, we don't have a direct equivalent of Java's static methods or constructors with parameters, so I used classmethods and instance methods instead.

Also, I did not implement the `process_debug_symbol` method, as it is not clear what this method should do based on the provided Java code. You will need to implement this method in your Python code depending on how you want to handle debug symbols.