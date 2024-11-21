Here's the translation of the given Java code into equivalent Python:

```Python
class DebuggerModelFactory:
    def __init__(self):
        pass

    def is_compatible(self) -> bool:
        return True


# Note: The following imports are not necessary for this specific conversion,
#       but they might be useful in a larger context.
from abc import ABC, abstractmethod
import ghidra.util.classfinder.extension_point as ExtensionPoint
```

In the above Python code:

- We define a class `DebuggerModelFactory` that inherits from nothing (equivalent to Java's interface).
- The method `is_compatible()` is equivalent to the default method in Java.
- Note: In Python, we don't have direct equivalents of Java interfaces or abstract classes. Instead, we use inheritance and polymorphism to achieve similar results.

The above code does not include any imports from other modules (like `ghidra`), as they are specific to your project's context.