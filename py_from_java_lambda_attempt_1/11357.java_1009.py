Here is the translation of the Java interface `RegisterState` to a Python class:

```python
from typing import Set, List

class RegisterState:
    def get_keys(self) -> Set[str]:
        pass  # implement this method in your subclass

    def get_vals(self, key: str) -> List[bytes]:
        pass  # implement this method in your subclass

    def is_initialized(self, key: str) -> List[bool]:
        pass  # implement this method in your subclass

    def set_vals(self, key: str, vals: bytes | int, size: int = None, set_initialised: bool = False):
        pass  # implement this method in your subclass

    def dispose(self):
        pass  # implement this method in your subclass
```

Note that I've used Python's type hints to indicate the expected types of the methods' return values and parameters. However, since these are abstract methods defined by an interface, they don't actually need to be implemented in this class itself - you would typically create a concrete subclass that implements each method according to your specific needs.

Also, I've used Python's `bytes` type instead of Java's `byte[]`, as well as the `int | None` syntax for the `size` parameter (which allows it to accept either an integer or no value).