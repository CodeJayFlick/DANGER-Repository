Here is the translation of the given Java code into equivalent Python:

```Python
from typing import Optional

class RocksDbConfig:
    def __init__(self):
        self._db_path: str = None

    @property
    def db_path(self) -> Optional[str]:
        return self._db_path

    @db_path.setter
    def db_path(self, value: str) -> None:
        self._db_path = value

    def with_db_path(self, db_path: str) -> 'RocksDbConfig':
        self.db_path = db_path
        return self


# Note that Python does not have a direct equivalent to Java's @Value.Immutable annotation.
```

In this translation:

- The `@Nullable` and `@Value.Immutable` annotations are removed as they do not exist in Python.

- A class `RocksDbConfig` is defined with an instance variable `_db_path`.

- A property `db_path` is added to the class, which allows you to get or set the value of `_db_path`. The getter returns the current value and the setter sets a new value for `_db_path`.

- A method `with_db_path` is added that takes a string as an argument. It updates the value of `_db_path` with this string and then returns itself (a common pattern in Python).