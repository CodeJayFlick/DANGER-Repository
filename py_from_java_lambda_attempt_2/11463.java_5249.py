Here is the translation of the Java code to Python:
```
class Label:
    def __init__(self):
        pass

    def long_value(self, buf: 'MemBuffer', off: int) -> int:
        return buf.get_address().get_offset() + off

    def length(self, buf: 'MemBuffer', off: int) -> int:
        return 0
```
Note that I've used type hints for the function parameters and return types to make it clear what types are expected.