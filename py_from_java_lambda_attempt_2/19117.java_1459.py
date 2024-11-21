Here is the translation of the given Java interface into a Python class:

```Python
class Diff:
    def __init__(self, key: str, from_value=None, to_value=None):
        self.key = key
        self.from_value = from_value
        self.to_value = to_value

    @property
    def get_key(self) -> str:
        return self.key

    @property
    def get_from_value(self) -> Optional['any']:
        return self.from_value

    @property
    def get_to_value(self) -> Optional['any']:
        return self.to_value

def of(key: str, from_value=None, to_value=None):
    return Diff(key, from_value, to_value)
```

Please note that Python does not have a direct equivalent for Java's `@Immutable` annotation. The above code is just an implementation in Python and does not provide any guarantees about the immutability of the class.

Also, since there was no specific type defined for VALUE in the original Java interface, I used 'any' as the return type for get_from_value() and get_to_value().