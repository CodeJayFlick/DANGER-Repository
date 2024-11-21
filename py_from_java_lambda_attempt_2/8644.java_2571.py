Here is the translation of the Java interface `DiffControllerListener` to a Python class:

```python
class DiffControllerListener:
    def __init__(self):
        pass  # No initialization needed in this case

    def diff_location_changed(self, diff_control: 'ghidra_diff_controller', location: int) -> None:
        """Called when the difference location changes"""
        raise NotImplementedError("Method must be implemented by subclass")

    def differences_changed(self, diff_control: 'ghidra_diff_controller') -> None:
        """Called when the differences change"""
        raise NotImplementedError("Method must be implemented by subclass")
```

Note that I've used type hints for the method parameters and return types. In Python 3.x, you can use string literals as type hints to indicate that a class or function is intended to work with specific classes or functions from other modules.

The `__init__` method is empty because there's no initialization needed in this case (i.e., we're not storing any state). The two methods are abstract and raise a `NotImplementedError`, indicating that they must be implemented by subclasses.