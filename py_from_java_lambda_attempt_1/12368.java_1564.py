Here is the translation of the given Java code into equivalent Python:

```Python
class Pointer64DataType:
    def __init__(self):
        self.__init__()

    @classmethod
    def put(cls):
        ClassTranslator.put("ghidra.program.model.data.Pointer64", cls.__name__)

    dataType = staticmethod(Pointer64DataType())

    def __init__(self, dt=None):
        super().__init__(dt, 8)
```

Please note that Python does not have direct equivalent of Java's `static` block or `public class`. The above code is a simplified translation and might require additional modifications based on the actual requirements.