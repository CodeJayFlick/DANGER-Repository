Here is the translation of the Java code to Python:
```
class LoadFileException(Exception):
    def __init__(self, message=None, ts_status_code=TSStatusCode.LOAD_FILE_ERROR.value):
        super().__init__(message)
        self.ts_status_code = ts_status_code
```
Note that I've assumed `TSStatusCode` is a separate class or module with an attribute `LOAD_FILE_ERROR`. If it's not the case, you'll need to provide more context.

Also, in Python, we don't have explicit constructors like Java does. Instead, we define the `__init__` method which gets called when an instance of the class is created. The `super().__init__(message)` line calls the parent class' constructor (in this case, the built-in `Exception` class) with the provided message.

The rest of the code remains similar to Java: we're defining a custom exception class that inherits from the base `Exception` class and has an additional attribute `ts_status_code`.