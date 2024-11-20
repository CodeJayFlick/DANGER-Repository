Here is the translation of the given Java code into equivalent Python:

```Python
from abc import ABC, abstractmethod

class AdjustableNonTransactionalDatabaseAdapterConfig(ABC):
    @abstractmethod
    def with_parents_per_global_commit(self, parents_per_global_commit: int) -> 'AdjustableNonTransactionalDatabaseAdapterConfig':
        pass


# This is not a direct translation of the Java code but it's equivalent in Python.
class NonTransactionalDatabaseAdapterConfig:
    pass

class AdjustableDatabaseAdapterConfig:
    pass
```

Note that this is an abstract class and method, which means they cannot be instantiated or called directly. They are meant to be subclassed and implemented by concrete classes.

Also note that the `@Value.Immutable` annotation in Java does not have a direct equivalent in Python. The concept of immutable objects is also different between languages.