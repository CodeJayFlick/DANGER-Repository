Here is the translation of the Java code to Python:
```python
import sqlite3
from typing import Any, TypeVar

T = TypeVar('T')

class JdbcSelectSpliterator:
    def __init__(self, conn: sqlite3.Connection, sql: str, prepare_statement: callable, deserializer: callable):
        self.conn = conn
        self.sql = sql
        self.prepare_statement = prepare_statement
        self.deserializer = deserializer

    def to_stream(self) -> Any:
        return StreamSupport.stream(self, False).on_close(lambda: self.close_resources())

    def close_resources(self):
        for closeable in reversed(list(self.closeables)):
            try:
                closeable.close()
            except Exception as e:
                if not hasattr(e, 'add_suppressed'):
                    raise
                else:
                    e.add_suppressed(e)

    @property
    def done(self) -> bool:
        return self._done

    @done.setter
    def done(self, value: bool):
        self._done = value

    _done = False
    closeables = []

def prepare_statement(ps: sqlite3.PreparedStatement) -> None:
    pass  # implement your logic here

def deserializer(rs: sqlite3.ResultSet) -> T:
    pass  # implement your logic here

@staticmethod
def build_stream(conn: sqlite3.Connection, sql: str, prepare_statement: callable, deserializer: callable) -> Any:
    return JdbcSelectSpliterator(conn, sql, prepare_statement, deserializer).to_stream()

class StreamSupport:
    @staticmethod
    def stream(spliterator: 'JdbcSelectSpliterator', parallel: bool = False) -> Any:
        pass  # implement your logic here

    @staticmethod
    def on_close(func: callable) -> None:
        pass  # implement your logic here
```
Note that I've used the `sqlite3` library to interact with the database, and implemented some of the Java code as Python functions. The rest is left for you to fill in!