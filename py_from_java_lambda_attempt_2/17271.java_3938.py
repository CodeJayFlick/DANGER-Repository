Here is the translation of the Java code to Python:
```
class ShowLockInfoOperator:
    def __init__(self, token_int_type: int, partial_path: 'PartialPath') -> None:
        super().__init__(token_int_type)
        self.path = partial_path

    @property
    def path(self) -> 'PartialPath':
        return self._path

class PartialPath:
    pass  # This is a placeholder for the Python equivalent of Java's PartialPath class, which you would need to implement separately in Python.
```
Note that I've used type hints and the `@property` decorator to mimic some aspects of Java's syntax. However, keep in mind that this translation is not exact, as Python has different built-in features and idioms than Java.

In particular:

* In Python, we don't need a separate class for `PartialPath`, but rather can use an existing data structure (e.g., a string or a custom object) to represent the path.
* The `super()` call is used in Python to invoke the constructor of the parent class. However, since this code doesn't actually inherit from another class, it's not strictly necessary here.

I hope this helps! Let me know if you have any further questions.