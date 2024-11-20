Here is the translation of the Java code to Python:
```
class NoFunctionGraphViewSettings(FunctionGraphViewSettings):
    def __init__(self):
        # limited usage constructor
        pass

    def __init__(self, copy_settings: FunctionGraphViewSettings):
        super().__init__(copy_settings)
```
Note that I've used the `pass` statement in the first `__init__` method to indicate that it does nothing. In Python, you don't need a separate "no-op" constructor like Java has.

Also, I've assumed that `FunctionGraphViewSettings` is a class defined elsewhere in your codebase. If not, please let me know and I can help with that as well!