Here is the translation of the Java code to Python:
```
import typing as t

class MongoClientConfig(t.Generic):
    def __init__(self, client: 'MongoClient', connection_string: str = None, database_name: str = None) -> None:
        self.client = client
        self.connection_string = connection_string
        self.database_name = database_name

    @classmethod
    def of(cls, client: 'MongoClient') -> 'MongoClientConfig':
        return cls(client)

    @property
    def connection_string(self) -> t.Optional[str]:
        return self._connection_string

    @connection_string.setter
    def connection_string(self, value: str) -> None:
        self._connection_string = value

    @property
    def database_name(self) -> t.Optional[str]:
        return self._database_name

    @database_name.setter
    def database_name(self, value: str) -> None:
        self._database_name = value

    @property
    def client(self) -> 'MongoClient':
        return self._client

    @client.setter
    def client(self, value: 'MongoClient') -> None:
        self._client = value

    def with_connection_string(self, connection_string: str) -> 'MongoClientConfig':
        self.connection_string = connection_string
        return self

    def with_database_name(self, database_name: str) -> 'MongoClientConfig':
        self.database_name = database_name
        return self

    def with_client(self, client: 'MongoClient') -> 'MongoClientConfig':
        self.client = client
        return self
```
Note that I used the `typing` module to define a generic class and type hints. I also replaced the Java-style annotations (e.g., `@Value.Immutable`) with Python's built-in property decorators (e.g., `@property`).