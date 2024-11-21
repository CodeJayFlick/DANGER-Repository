Here is the translation of the given Java code into Python:

```Python
class Modem:
    def __init__(self):
        pass

    def accept(self, modem_visitor):
        raise NotImplementedError("Method 'accept' must be implemented by subclass")
```

Note that in this Python version, we're using a class-based approach to define an abstract base class (ABC) `Modem`. The `__init__` method is used for initialization and the `accept` method is declared as abstract.