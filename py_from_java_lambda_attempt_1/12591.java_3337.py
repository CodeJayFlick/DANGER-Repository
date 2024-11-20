Here is the translation of the given Java code into Python:

```Python
class LiveMemoryListener:
    def __init__(self):
        pass

    def memory_changed(self, addr: int, size: int) -> None:
        """Callback for when memory changes"""
        pass
```

Note that in this translation, I've used a class `LiveMemoryListener` with an initializer method (`__init__`) and the callback method `memory_changed`. The `addr` and `size` parameters are now integers instead of Java's `Address` type.