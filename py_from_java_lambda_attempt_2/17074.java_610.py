Here is the translation of the Java code to Python:
```
class IndexManagerException(Exception):
    def __init__(self, message):
        super().__init__(message)

    def __init__(self, e):
        if isinstance(e, Exception):
            super().__init__(str(e))
        else:
            raise ValueError("Invalid exception type")
```
Note that in Python, we don't need to specify the `serialVersionUID` as it is not used in Python. Also, I've removed the package declaration and imports as they are not necessary in Python.

The `IndexManagerException` class inherits from the built-in `Exception` class in Python. The constructor takes a message string or another exception object as input. If an exception object is passed, its error message will be used to create a new exception with the same message.