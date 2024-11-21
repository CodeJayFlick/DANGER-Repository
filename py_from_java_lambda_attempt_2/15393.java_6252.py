Here is the translation of the Java interface `ai.djl.DeviceType` into a Python class:

```python
class DeviceType:
    def __init__(self):
        pass

    @staticmethod
    def to_device_type(device: str) -> int:
        return 0

    @staticmethod
    def from_device_type(device_type: int) -> str | None:
        return None
```

Note that Python does not have a direct equivalent of Java's `interface` keyword. Instead, we define a class with static methods to achieve similar functionality.

Also, in the translation process, I replaced the Java-specific types (e.g., `public`, `static`) and syntax (e.g., method declarations) with their Python equivalents.