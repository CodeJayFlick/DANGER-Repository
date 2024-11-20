Here's the translation of the given Java code into Python:

```Python
class PrivateSaveable:
    def __init__(self):
        pass

    def is_private(self) -> bool:
        return True


from abc import ABC, abstractmethod


class Saveable(ABC):
    @abstractmethod
    def is_private(self) -> bool:
        pass
```

Note that Python does not have a direct equivalent to Java's `public`, `abstract`, and `@Override` keywords. The `is_private()` method in the original code seems to be meant for signaling whether this saveable should broadcast its changes or not, so I've translated it into a simple boolean return value in the Python version.