Here is the translation of the Java code to Python:
```
class ResourceStringInfo:
    def __init__(self, address: int, string: str, length: int):
        self.address = address
        self.string = string
        self.length = length

    @property
    def address(self) -> int:
        return self.address

    @property
    def string(self) -> str:
        return self.string

    @property
    def length(self) -> int:
        return self.length
```
Note that I've used Python's `@property` decorator to create read-only properties for the attributes, which is equivalent to Java's getter methods.