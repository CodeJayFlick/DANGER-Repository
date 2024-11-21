Here is the translation of the Java code to Python:
```
class LoadEmptyFileException(Exception):
    def __init__(self):
        super().__init__("Cannot load an empty file")
```
Note that in Python, we don't need a `package` declaration or any other boilerplate code. We can simply define a class that inherits from the built-in `Exception` class and override its constructor to set the error message.

The `super()` call is used to invoke the constructor of the parent class (`Exception`) with the specified argument, which sets the error message for this exception.