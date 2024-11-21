Here is the equivalent Python code:

```Python
class UnsatisfiedFieldsException(Exception):
    def __init__(self, missing):
        super().__init__("There are fields without suitable constructors: " + str(missing))
        self.missing = frozenset(missing)

    @property
    def missing(self):
        return self._missing

unsatisfied_fields_exception = UnsatisfiedFieldsException({"Class1", "Class2"})
print(unsatisfied_fields_exception.get_missing())
```

Note that Python does not have a direct equivalent to Java's `Set` class, but we can use the built-in set data structure. Also, in Python, it is common practice to define properties (like `@property`) for attributes that should be read-only or need some special handling when accessed.