Here is the translation of the given Java code into equivalent Python:

```Python
class MDIntDataType:
    def __init__(self):
        pass

    @property
    def type_name(self) -> str:
        return "int"
```

Note that this is a simplified version, as there are some differences between Java and Python. Here's what I did differently:

- In the constructor (`__init__` method), I didn't include any parameters or calls to `super()`, since these concepts don't directly translate from Java.
- The `getTypeName()` method in Java is equivalent to a property (a getter) in Python, which returns "int" when called.