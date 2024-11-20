Here's a translation of the Java interface into equivalent Python:

```Python
from typing import TypeVar, Any

T = TypeVar('T')

class AsyncResult:
    def __init__(self):
        pass

    @property
    def is_completed(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def get_value(self) -> T | None:
        raise NotImplementedError("Subclasses must implement this method")

    def await(self) -> None:
        raise NotImplementedError("Subclasses must implement this method")
```

Note that in Python, we don't have direct equivalents to Java's interfaces or classes. Instead, we use abstract base classes (ABCs), which are implemented by subclasses.

The `AsyncResult` class is an ABC that defines the methods and properties of the interface. The `is_completed`, `get_value`, and `await` methods are declared as abstract using the `@property` decorator for `is_completed`. This means any subclass must implement these methods, or else they will raise a `NotImplementedError`.

The type hinting is used to indicate that the return types of these methods should be compatible with the generic type parameter `T`, which represents the result type.