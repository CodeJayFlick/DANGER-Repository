Here is the translation of the Java code to Python:
```
class DebugSymbolName:
    def __init__(self, name: str, offset: int):
        self.name = name
        self.offset = offset

    def __str__(self) -> str:
        return f"<{offset:016x}: {name}>"
```
Note that I've used Python's type hints to indicate the types of the `name` and `offset` parameters, as well as the return value of the `__str__` method. This is not strictly necessary for a simple class like this one, but it can be helpful for documentation purposes.

Also, in the `__str__` method, I've used Python's f-strings to format the string. The `{offset:016x}` part formats the offset as a 16-digit hexadecimal number, and the `{name}` part simply inserts the value of the `name` attribute into the string.