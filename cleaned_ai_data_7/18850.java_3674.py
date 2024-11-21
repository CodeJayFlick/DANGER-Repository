import uuid
from enum import Enum

class Type(Enum):
    UNKNOWN = 0
    ICEBERG_TABLE = 1
    DELTA_LAKE_TABLE = 2
    VIEW = 3


class Contents:
    def __init__(self):
        self._id = str(uuid.uuid4())

    @property
    def id(self) -> str:
        return self._id

    def unwrap(self, clazz: type) -> Optional:
        if issubclass(clazz, type(self)):
            return Optional.of(type(self)(clazz))
        else:
            return Optional.empty()


class IcebergTable(Contents):
    pass


class DeltaLakeTable(Contents):
    pass


class SqlView(Contents):
    pass
