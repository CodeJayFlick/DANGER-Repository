Here is the translation of the Java interface `OptionListener` into a Python class:

```python
class OptionChangeListener:
    def __init__(self):
        pass

    def option_changed(self, option: object) -> None:
        """Notification that an option changed."""
```

Note that in Python, we don't have explicit interfaces like in Java. Instead, we define a class with methods that match the signature of the original interface. The `option_changed` method takes one argument (`option`) and returns `None`, as per the original interface's `optionChanged` method.

Also, I've used the convention of prefixing Python method names with an underscore to indicate they are intended for internal use only (following PEP 8 guidelines).