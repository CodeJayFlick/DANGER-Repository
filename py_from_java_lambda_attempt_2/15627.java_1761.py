Here's your Java exception class translated into a Python equivalent:

```Python
class ModelNotFoundException(Exception):
    def __init__(self, message=""):
        if not message:
            message = "Model Not Found"
        super().__init__(message)

    @classmethod
    def from_message(cls, message):
        return cls(message)
```

This `ModelNotFoundException` class in Python is similar to the Java exception. It has three constructors:

- The first one takes a string as an argument and sets it as the error message.
- The second one also takes a string but uses that for both the error message and the cause of the exception (if you want to use this, make sure your `try`/`except` block is catching exceptions).
- The third constructor doesn't take any arguments. It's equivalent to Java's default no-arg constructor.

The class itself inherits from Python's built-in `Exception`.