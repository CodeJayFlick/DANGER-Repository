Here's how you can translate this Java code into equivalent Python:

```Python
class TrainingDivergedException(Exception):
    def __init__(self, message=""):
        super().__init__(message)

    @classmethod
    def from_message(cls, message):
        return cls(message)
```

In the above translation:
- The `TrainingDivergedException` class is defined in Python. It inherits from the built-in `Exception` class.
- There are three constructors (`__init__`) provided for this exception: 
  - One that takes a single string argument, which sets the message of the exception to that value.
  - Another one that also takes two arguments (message and cause), similar to Java's constructor. The Python equivalent is `super().__init__(message, cause)`.
- A class method (`from_message`) is provided for convenience, allowing you to create a new instance with just a message.

Note: In Python, we don't need to explicitly define serialVersionUID as it is not necessary in Python.