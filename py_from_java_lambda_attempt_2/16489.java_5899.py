Here is the translation of the Java interface `TimeseriesSchemaSnapshot` to a Python class:

```python
from typing import Collection

class TimeseriesSchemaSnapshot:
    def get_timeseries_schemas(self) -> Collection:
        pass  # implement this method in your subclass

    def set_timeseries_schemas(self, schemas: Collection):
        pass  # implement this method in your subclass
```

Note that I've used the `typing` module to define a type hint for the `get_timeseries_schemas()` and `set_timeseries_schemas()` methods. This is not strictly necessary, but it can help with code readability and maintainability.

Also note that Python does not have an exact equivalent of Java's interface concept. Instead, we use abstract base classes (ABCs) or protocols to define a set of methods that must be implemented by any subclass. In this case, I've defined the `TimeseriesSchemaSnapshot` class as an ABC using the `class` keyword and leaving the implementation details blank (`pass`). Any subclass of this class will need to implement these two methods.