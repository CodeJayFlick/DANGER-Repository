Here is the translation of the Java interface into a Python class:

```Python
class GdbConsoleOutputListener:
    def __init__(self):
        pass

    def output(self, channel: str, out: str) -> None:
        """GDB outputted some text"""
```

Note that in Python, we don't have an equivalent to Java's `interface` keyword. Instead, we define a class with methods (in this case, the single method `output`). The `__init__` method is called when an instance of the class is created; it doesn't do anything here because there are no attributes to initialize.

The `output` method takes two parameters: `channel`, which should be either `'stderr'` or `'stdout'`, and `out`, a string representing the output.