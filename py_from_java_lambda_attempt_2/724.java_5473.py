Here is the translation of the Java code to Python:

```Python
class DbgSection:
    def __init__(self, start: int, end: int, size: int, offset: int, objfile: str):
        self.start = start
        self.end = end
        self.size = size
        self.offset = offset
        self.objfile = objfile

        assert start + size == end

    def get_start(self) -> int:
        return self.start

    def get_end(self) -> int:
        return self.end

    def get_size(self) -> int:
        return self.size

    def get_offset(self) -> int:
        return self.offset

    def get_objfile(self) -> str:
        return self.objfile
```

Note that I've used type hints for the method parameters and return types, as well as for the instance variables. This is not strictly necessary in Python 3.x, but it can be helpful for documentation purposes and for catching errors at runtime.