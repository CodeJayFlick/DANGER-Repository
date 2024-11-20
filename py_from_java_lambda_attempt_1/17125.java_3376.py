Here is the translation of the Java code to Python:
```
class UDFFailure(Exception):
    def __init__(self, message: str, cause=None) -> None:
        super().__init__(message)
        self.cause = cause
```
Note that I've used a custom exception class `UDFFailure` instead of inheriting from the built-in `Exception`. This is because Python's exceptions are not as strongly typed as Java's, and using a custom class allows us to add additional attributes (like `cause`) in a more explicit way.

The two constructors (`__init__` methods) are equivalent to the original Java code:

* The first constructor takes an optional `cause` parameter, which is set on the exception instance.
* The second constructor only takes a single `message` parameter and sets it as the exception message.