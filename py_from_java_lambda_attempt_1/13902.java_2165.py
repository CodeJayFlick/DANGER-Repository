Here is the translation of the given Java code into Python:

```Python
class Database:
    def __init__(self):
        pass

    def add(self, obj) -> T:
        raise NotImplementedError("Method 'add' must be implemented by subclass")

    def get(self, id: str) -> T:
        raise NotImplementedError("Method 'get' must be implemented by subclass")
```

Note that in Python, we don't have a direct equivalent of Java's generics. However, you can achieve similar functionality using type hints and abstract methods.

The `add` method is declared as an abstract method (using the `raise NotImplementedError`) because it needs to be implemented by any concrete subclasses. Similarly for the `get` method.