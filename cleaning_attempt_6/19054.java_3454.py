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
