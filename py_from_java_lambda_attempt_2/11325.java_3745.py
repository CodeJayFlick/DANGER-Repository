Here is the equivalent Python code for the given Java class:

```Python
class RollbackException(Exception):
    def __init__(self, message=None, cause=None):
        if cause:
            super().__init__(str(message) + " (caused by: {})".format(str(cause)), cause)
        elif message:
            super().__init__(message)
        else:
            super().__init__()
```

This Python class `RollbackException` is a subclass of the built-in `Exception`. It has three constructors:

- The first one takes an optional `cause`, which will be used to set both the exception's message and its cause.
- The second one takes only an optional `message`.
- The third one also takes two parameters: `message` (which sets the exception's message) and `cause`.