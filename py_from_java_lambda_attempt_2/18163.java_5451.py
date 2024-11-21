Here is the translation of the Java code to Python:
```
class TsFileDecodingException(Exception):
    def __init__(self, message=None, cause=None):
        if message is None:
            super().__init__()
        else:
            super().__init__(message)
        if cause is not None:
            self.__cause__ = cause

serialVersionUID = -8632392900655017028L
```
Note that:

* In Python, we don't need to specify a package name or import statements for the exception class.
* The `extends` keyword in Java is equivalent to inheritance in Python. We define a new class `TsFileDecodingException` that inherits from the built-in `Exception` class.
* The constructor (`__init__`) takes two optional arguments: `message` and `cause`. If no message is provided, we simply call the parent's constructor with no argument. Similarly, if no cause is provided, we don't set it explicitly.
* We use the `super()` function to call the parent's constructor (in this case, the built-in `Exception` class).
* The `serialVersionUID` constant is defined as a Python integer literal.

That's it!