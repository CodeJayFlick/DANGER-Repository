Here is the translation of the Java code to Python:
```
class FilteredBytesAndDisassembly:
    def __init__(self, filtered_bytes: list[str], disassembly: list[str]):
        self.filtered_bytes = filtered_bytes
        self.disassembly_string = disassembly

    @property
    def filtered_bytes(self) -> list[str]:
        return self.filtered_bytes

    @property
    def disassembly(self) -> list[str]:
        return self.disassembly_string
```
Note that I used the `@property` decorator to create read-only properties for the `filtered_bytes` and `disassembly` attributes. This is equivalent to the getter methods in Java.

Also, I used type hints (`list[str]`) to indicate the types of the arguments and return values. Python 3.5+ supports this syntax, which can help with code readability and static analysis tools.