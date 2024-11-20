Here is the equivalent Python code:

```Python
class CompilerSpecID:
    def __init__(self, compiler_id):
        self.compiler_id = compiler_id

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        if not isinstance(value, str) or len(value.strip()) == 0:
            raise ValueError("Compiler ID cannot be null or empty")
        self._id = value

    def __str__(self):
        return self.id

    def __eq__(self, other):
        if not isinstance(other, CompilerSpecID):
            return False
        return self.id.lower() == other.id.lower()

    def __lt__(self, other):
        return self.id.lower() < other.id.lower()
```

Note that Python does not have a direct equivalent to Java's `Comparable` interface. The `__eq__`, `__lt__`, etc., methods are used for comparison in Python.

Also note that the `idAsString()` method is not necessary, as you can directly return the value of the `compiler_id` attribute when calling `str(CompilerSpecID)`.