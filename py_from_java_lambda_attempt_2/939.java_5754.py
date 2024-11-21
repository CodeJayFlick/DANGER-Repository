Here is the translation of the Java interface `DebugHostSymbol1` into a Python class:

```python
class DebugHostSymbol1:
    def compare_against(self, comparison_symbol: 'DebugHostSymbol1', comparison_flags: int) -> int:
        pass  # implement this method in your subclass

    @property
    def as_base_class(self):
        raise NotImplementedError("asBaseClass not implemented")

    @property
    def as_constant(self):
        raise NotImplementedError("asConstant not implemented")

    @property
    def as_data(self):
        raise NotImplementedError("asData not implemented")

    @property
    def as_field(self):
        raise NotImplementedError("asField not implemented")

    @property
    def as_module(self) -> 'DebugHostModule1':
        raise NotImplementedError("asModule not implemented")

    @property
    def as_public(self):
        raise NotImplementedError("asPublic not implemented")
```

Note that I've used Python's `@property` decorator to create read-only properties for the various methods. This is equivalent to Java's getter methods, but in Python, you don't need explicit getters and setters.

Also, since this is an interface (in Java) or abstract class (in Python), all the methods are declared as abstract (`pass`) or raise a `NotImplementedError` when called directly on the base class. You would implement these methods in your concrete subclass(es).