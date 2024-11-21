Here is the translation of the given Java interface into a Python class:

```Python
from typing import TypeVar, Optional

class Put:
    def __init__(self, key: 'Key', value: object):
        self.key = key
        self.value = value
        self.expected_value: Optional[object] = None

    @property
    def expected_value(self) -> Optional[object]:
        return self.expected_value

    @expected_value.setter
    def expected_value(self, expected_value: object):
        self.expected_value = expected_value

def of(key: 'Key', value: object) -> 'Put':
    return Put(key, value)

def of_with_expected_value(key: 'Key', value: object, expected_value: object) -> 'Put':
    return Put(key, value).expected_value = expected_value
```

Note that Python does not have a direct equivalent to Java's interfaces. Instead, we can use abstract base classes (ABCs) or protocols if you're using type hints and the typing module.

Also note that in this translation:

- The `@Value.Immutable` annotation is ignored as it has no direct equivalent in Python.
- The `@Nonnull`, `@Nullable` annotations are also ignored. In Python, these would be handled through type hinting (e.g., with Optional).
- The Java methods (`getValue()`, `getExpectedValue()`) have been replaced by properties and a setter method for the expected value.

The class is designed to mimic the behavior of the original interface in terms of its constructor parameters and methods.