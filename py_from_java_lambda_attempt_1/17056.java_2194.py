Here is the translation of the Java code to Python:
```
class SinkException(Exception):
    def __init__(self, message):
        super().__init__(message)

    def __init__(self, message, cause):
        super().__init__(message, cause)
```
Note that in Python, we don't need to specify a package name or use the `public` keyword. The class is simply defined as `SinkException`. Also, the constructor (`__init__`) method takes two arguments: `message` and `cause`, which are passed directly to the parent class's constructor using the `super()` function.

That's it!