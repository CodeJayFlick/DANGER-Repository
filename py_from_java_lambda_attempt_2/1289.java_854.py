Here is the translation of the given Java code into equivalent Python:

```Python
class GdbCommandRunningEvent:
    def __init__(self, tail=None):
        if tail is None:
            self.tail = GdbMiFieldList()
        else:
            try:
                super().__init__(tail)
            except Exception as e:
                raise GdbParseError from e

    @property
    def state(self) -> 'GdbState':
        return None  # Let running cause change, as it has more info.
```

Note that Python does not have direct equivalent of Java's `package`, `import` statements. Also, Python uses indentation to denote block-level structure, unlike Java which uses curly braces.

The class itself is defined in a similar way, with the constructor (`__init__`) and property (using the `@property` decorator) being implemented as per their Java counterparts.