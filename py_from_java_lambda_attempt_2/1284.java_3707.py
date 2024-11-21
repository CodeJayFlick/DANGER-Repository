Here is the translation of the given Java code into equivalent Python:

```Python
class GdbCommandConnectedEvent:
    def __init__(self, tail):
        super().__init__(tail)
```

Note that this Python class does not include any error handling for parsing errors as was present in the original Java code. If you want to add such functionality, you would need to use a try-except block and raise an exception if the parsing fails.

Here is how you could modify the `__init__` method to handle parsing errors:

```Python
class GdbCommandConnectedEvent:
    def __init__(self, tail):
        try:
            super().__init__(tail)
        except Exception as e:
            # Handle the error here. For example, raise a custom exception.
            raise GdbParseError("Failed to parse the tail") from e
```

In this modified version of `__init__`, if any exception occurs during parsing (which is caught by the try-except block), it will be re-raised as a `GdbParseError` with an appropriate error message.