Here is the translation of the given Java interface into a Python class:

```Python
from typing import Any, Dict, List

class TargetMemory:
    def read_memory(self, address: int, length: int) -> Any:
        # Implement your logic here to read memory at the given address and return it as bytes.
        pass

    def write_memory(self, address: int, data: bytes) -> None:
        # Implement your logic here to write memory at the given address with the provided data.
        pass

    def get_regions(self) -> Dict[str, Any]:
        # Implement your logic here to fetch and return regions of valid addresses as a dictionary.
        pass
```

Note that Python does not have direct equivalents for Java's interfaces or annotations. In this translation, I've used Python classes with methods instead of an interface in Java. The `@DebuggerTargetObjectIface("Memory")` annotation is also missing because there isn't a direct equivalent in Python.