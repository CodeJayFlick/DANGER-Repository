Here is the translation of the Java interface `AsyncSequenceHandlerForRunner` to a Python class:

```python
from typing import Any, TypeVar

R = TypeVar('R')

class AsyncSequenceHandler:
    def __init__(self):
        pass

    def next(self, v: Any, exc: Exception) -> None:
        raise NotImplementedError("Subclasses must implement this method")

    def next_ignore(self, result: Any, exc: Exception) -> None:
        self.next(None, exc)
```

Note that I've used the `TypeVar` from the `typing` module to define a type variable `R`, which is equivalent to the Java generic parameter `<R>` in the original interface. In Python, we don't have direct support for generics like Java does, but using `TypeVar` allows us to create type variables that can be used as placeholders for types.

The rest of the translation involves creating a Python class with two methods: `next` and `next_ignore`. The `next` method is abstract (i.e., it raises an exception when called) because in Java, interfaces cannot have concrete implementations. In Python, we don't need to worry about this; instead, we can simply raise a `NotImplementedError`.

The `next_ignore` method is implemented as a simple wrapper around the `next` method, passing `None` and the given exception as arguments.

This translation maintains the same interface (pun intended) as the original Java code but adapts it to Python's syntax and semantics.