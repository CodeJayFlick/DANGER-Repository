Here's the equivalent Python code:

```Python
class UDFAttributeNotProvidedException(Exception):
    def __init__(self, required_attribute):
        super().__init__(f"attribute '{required_attribute}' is required but was not provided.")
```

Note that in Python, we don't need to specify a package name or import any modules. The `Exception` class is built-in and can be used directly.