Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractWrapperTypeColumnRenderer:
    def __init__(self):
        pass

    # Overridden to only allow the constraint filtering mechanism.
    def get_column_constraint_filter_mode(self) -> str:
        return "ALLOW_CONSTRAINTS_FILTER_ONLY"

    def get_filter_string(self, t: object, settings: dict) -> str:
        raise Exception("We don't use String values for filtering wrapper types")
```

Please note that Python does not have direct equivalent of Java's interfaces. In Python, we can achieve similar functionality using abstract classes or by defining a protocol (a set of methods that must be implemented).