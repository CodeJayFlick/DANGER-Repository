from enum import Enum
import json

class SqlView:
    def __init__(self):
        pass

    @property
    def sql_text(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")

    @sql_text.setter
    def sql_text(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("SQL text must be a string")
        self._sql_text = value

    @property
    def dialect(self) -> 'Dialect':
        raise NotImplementedError("Subclasses must implement this method")

    @dialect.setter
    def dialect(self, value: 'Dialect') -> None:
        if not isinstance(value, Dialect):
            raise TypeError("Dialect must be a valid enum")
        self._dialect = value

class Dialect(Enum):
    HIVE = 1
    SPARK = 2
    DREMIO = 3
    PRESTO = 4
