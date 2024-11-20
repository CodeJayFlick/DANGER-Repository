Here is the translation of the given Java code into Python:

```Python
class NotEmptyException(Exception):
    """exception thrown whenever some container is expected to be empty and it isn't."""
    
    def __init__(self, message="Object was occupied.") -> None:
        super().__init__(message)

if __name__ == "__main__":
    try:
        raise NotEmptyException()
    except NotEmptyException as e:
        print(e)
```

In this Python code:

- We define a class `NotEmptyException` that inherits from the built-in Python exception class.
- The constructor (`__init__`) of our custom exception takes an optional message parameter. If no message is provided, it defaults to "Object was occupied.".
- In the main part of the script, we raise and catch this custom exception to demonstrate its usage.

Please note that Python does not have a direct equivalent for Java's `package` declaration or comments in the same style as Java.