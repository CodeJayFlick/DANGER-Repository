Here is the translation of the given Java code into Python:

```Python
class DiffTaskListener:
    NULL_LISTENER = lambda: None  # No-op listener that does nothing when task in progress changes.

    def __init__(self):
        pass

    def task_in_progress(self, in_progress: bool) -> None:
        """Signal the start and end of a diff task."""
        pass
```

Note that Python doesn't have an exact equivalent to Java's interface. Instead, we define a class with methods that are meant to be implemented by any subclass. The `NULL_LISTENER` is also defined as a lambda function in Python, which behaves similarly to the anonymous inner class in Java.