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
