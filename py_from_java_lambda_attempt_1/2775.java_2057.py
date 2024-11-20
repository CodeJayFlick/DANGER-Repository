Here is the translation of the Java code to Python:
```
class SleighLinkException(Exception):
    def __init__(self, message):
        super().__init__(message)
```
Note that in Python, we don't need a `public` keyword for classes or methods, and we use indentation instead of curly braces to define blocks. The `extends RuntimeException` part is not necessary in Python, as exceptions are first-class citizens and can be inherited from the built-in `Exception` class directly.