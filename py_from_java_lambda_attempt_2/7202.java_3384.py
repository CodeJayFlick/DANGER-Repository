Here is the translation of the given Java code into equivalent Python:

```Python
class OatQuickMethodHeader:
    def __init__(self):
        pass

    def get_code_size(self):
        raise NotImplementedError("Subclasses must implement this method")
```

Note that in Python, we don't have a direct equivalent to Java's abstract classes and methods. Instead, we use inheritance and the `NotImplementedError` exception to indicate that certain methods are not implemented by default.

In particular:

- The `__init__` method is used as a constructor.
- We define an empty class with no attributes or methods in this case.
- To achieve something similar to Java's abstract classes, we use inheritance and the `NotImplementedError` exception.