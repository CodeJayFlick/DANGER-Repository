Here is the translation of the Java code to Python:
```
class Callback:
    def __init__(self):
        pass

    @staticmethod
    def dummy():
        return lambda: None  # no-op

    @staticmethod
    def dummy_if_null(c=None):
        if c is None:
            return Callback.dummy()
        return c

    def call(self):
        raise NotImplementedError("Must be implemented by subclass")
```
Note that I've kept the `call` method abstract, as it's intended to be overridden by a subclass. In Python, we don't need an explicit interface or static methods like Java does.

Also, in Python, we use lambda functions for anonymous functions (similar to Java's `-> { ... }` syntax).