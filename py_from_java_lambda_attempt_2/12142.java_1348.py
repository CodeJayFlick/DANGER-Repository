Here's your Java interface translated into pure Python:

```Python
class AddressIterator:
    EMPTY_ITERATOR = type('EMPTY_ITERATOR', (), {
        'has_next': lambda self: False,
        '__next__': lambda self: None,
        'iter': lambda self: self
    })

    def __init__(self):
        pass

    def has_next(self):
        raise NotImplementedError("Subclasses must implement this method")

    def next(self):
        raise NotImplementedError("Subclasses must implement this method")
```

This Python code defines a class `AddressIterator` with an inner class `EMPTY_ITERATOR`. The interface methods are implemented as abstract methods in the base class, and overridden by the subclass.