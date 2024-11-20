Here is the translation of the Java code to Python:
```
class DecompileError(Exception):
    def __init__(self, type, msg):
        super().__init__(f"{type}: {msg}")

    def __str__(self):
        return f"DecompileError: {self.getMessage()}"

# Note: In Python, we don't need to specify the `serialVersionUID` as it's not used in this context
```
Note that I've renamed the class from `DecompileException` to `DecompileError`, which is a more conventional name for an exception class in Python.