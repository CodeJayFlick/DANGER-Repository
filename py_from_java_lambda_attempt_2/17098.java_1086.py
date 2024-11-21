Here's your Java code translated into Python:

```Python
class TemplateIsInUseException(Exception):
    def __init__(self, path: str) -> None:
        super().__init__(f"Template is in use on {path}")
```

Note that I've used the built-in `Exception` class as a base for your custom exception. The constructor (`__init__`) takes one argument, `path`, which it uses to create an error message.

The equivalent of Java's `TSStatusCode` and its method `getStatusCode()` is not directly available in Python. If you need similar functionality, you might want to consider using the `enum` module or a custom class for your status codes.