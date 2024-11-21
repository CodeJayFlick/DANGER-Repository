Here is the translation of the given Java code into equivalent Python:

```Python
class Unchanged:
    def __init__(self, key):
        self.key = key

    @property
    def should_match_hash(self) -> bool:
        return True


def unchanged(key: 'Key') -> 'Unchanged':
    return Unchanged(key)


# Note that in Java, you would have used an interface to define the Operation and V types.
# In Python, we can use abstract base classes (ABCs) or duck typing instead.

from abc import ABC, abstractmethod

class Operation(ABC):
    @abstractmethod
    def should_match_hash(self) -> bool:
        pass


class ValueOperation(Operation):
    pass
```

Note that in the translation from Java to Python:

- The `@Value.Immutable` annotation is not directly translatable into a similar concept in Python, as immutability is more of an implementation detail rather than something you would explicitly declare.
- In Python, we don't have direct equivalents for Java's interfaces and abstract classes. Instead, we use abstract base classes (ABCs) or duck typing to achieve similar functionality.
- The `@Nonnull` annotation in the original code has been replaced with a type hint (`-> 'Key'`) indicating that the function returns an object of type `'Unchanged'`.