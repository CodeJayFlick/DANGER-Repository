Here is the translation of the given Java code into equivalent Python:

```Python
class Pointer8DataType:
    def __init__(self):
        self.__init__()

    @classmethod
    def put(cls):
        ClassTranslator.put("ghidra.program.model.data.Pointer8", cls.__name__)

    dataType = None

    def __init__(self, dt=None):
        super().__init__()
```

Please note that Python does not have direct equivalent of Java's static block or class-level initialization. So we are using the `__init__` method to initialize the class and put the necessary information into ClassTranslator.

Also, in Python, you don't need a separate constructor for creating an instance of your class as it is already handled by the `__init__` method.