Here is the translation of the Java code to Python:
```
import typing as t

class TableModelLoader(t.Generic[T]):
    def load(self, accumulator: t.Any, monitor: t.Any) -> None:
        raise NotImplementedError
```
Note that I used the `t.Generic` type hint from the `typing` module to indicate that this class is a generic class with a type parameter `T`. The rest of the code is straightforward translation:

* The Java interface becomes a Python abstract base class (ABC).
* The method signature remains similar, but with some adjustments for Python's syntax and typing system.
* I used the `t.Any` type hint to indicate that the `accumulator` and `monitor` parameters can be any type. If you want to restrict these types further, you can modify this code accordingly.

This is a direct translation of the Java interface to Python; it does not include any additional functionality or modifications specific to Python.