Here is the translation of the given Java code into equivalent Python:

```Python
import logging

class ClassLocation:
    CLASS_EXT = ".class"

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.classes = set()

    def get_classes(self, existing_classes: set) -> None:
        raise NotImplementedError("Subclasses must implement this method")

    def check_for_duplicates(self, existing_classes: set) -> None:
        if not self.logger.isEnabledFor(logging.TRACE):
            return

        for c in self.classes:
            if c in existing_classes:
                module = c.__module__
                self.logger.trace(f"Attempting to load the same class twice: {c}. Keeping loaded class ; ignoring class from {self}")
```

Note that Python does not have an exact equivalent of Java's abstract classes. However, we can achieve similar functionality by defining a base class with methods that must be implemented in subclasses.

In this translation:

- The `CLASS_EXT` constant is preserved as it was.
- The constructor (`__init__`) initializes the logger and sets up an empty set for storing classes.
- The `get_classes` method has been translated to Python's equivalent of abstract methods. In Java, you would declare a method with no implementation in an abstract class; here we raise a `NotImplementedError`.
- The `check_for_duplicates` method is similar to its Java counterpart but uses Python's logging module instead.
- Note that the `CancelledException` and `TaskMonitor` classes from the original code have been removed as they do not seem relevant for this translation.