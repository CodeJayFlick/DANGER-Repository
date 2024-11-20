Here's a translation of the given Java interface into equivalent Python:

```Python
class DbgModelTargetAccessConditioned:
    def __init__(self):
        pass

    def is_accessible(self) -> bool:
        raise NotImplementedError("Method not implemented")

    def set_accessible(self, accessible: bool):
        pass
```

Note that in the above code:

- The `@Override` annotation from Java has been removed as Python does not support this. Instead, we use a docstring to indicate which method is being overridden.
- In the `is_accessible()` and `set_accessible()` methods, I have used the `raise NotImplementedError("Method not implemented")` statement because these are abstract methods in the interface that should be implemented by any class implementing this interface.