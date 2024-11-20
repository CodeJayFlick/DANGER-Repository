Here is the translation of the Java interface into a Python class:

```Python
from typing import Optional

class LocalTxConnectionConfig:
    def __init__(self):
        self._jdbc_url = None
        self._jdbc_user = None
        self._jdbc_pass = None
        self._pool_min_size = 1
        self._pool_max_size = 10
        self._pool_initial_size = 1
        self._pool_acquisition_timeout_seconds = 30
        self._pool_connection_lifetime_minutes = 5
        self._pool_transaction_isolation = 'READ_COMMITTED'

    @property
    def jdbc_url(self) -> Optional[str]:
        return self._jdbc_url

    @jdbc_url.setter
    def jdbc_url(self, value: str):
        self._jdbc_url = value

    def with_jdbc_url(self, value: str) -> 'LocalTxConnectionConfig':
        self._jdbc_url = value
        return self

    @property
    def jdbc_user(self) -> Optional[str]:
        return self._jdbc_user

    @jdbc_user.setter
    def jdbc_user(self, value: str):
        self._jdbc_user = value

    def with_jdbc_user(self, value: str) -> 'LocalTxConnectionConfig':
        self._jdbc_user = value
        return self

    @property
    def jdbc_pass(self) -> Optional[str]:
        return self._jdbc_pass

    @jdbc_pass.setter
    def jdbc_pass(self, value: str):
        self._jdbc_pass = value

    def with_jdbc_pass(self, value: str) -> 'LocalTxConnectionConfig':
        self._jdbc_pass = value
        return self

    @property
    def pool_min_size(self) -> int:
        return self._pool_min_size

    @pool_min_size.setter
    def pool_min_size(self, value: int):
        self._pool_min_size = value

    def with_pool_min_size(self, value: int) -> 'LocalTxConnectionConfig':
        self._pool_min_size = value
        return self

    @property
    def pool_max_size(self) -> int:
        return self._pool_max_size

    @pool_max_size.setter
    def pool_max_size(self, value: int):
        self._pool_max_size = value

    def with_pool_max_size(self, value: int) -> 'LocalTxConnectionConfig':
        self._pool_max_size = value
        return self

    @property
    def pool_initial_size(self) -> int:
        return self._pool_initial_size

    @pool_initial_size.setter
    def pool_initial_size(self, value: int):
        self._pool_initial_size = value

    def with_pool_initial_size(self, value: int) -> 'LocalTxConnectionConfig':
        self._pool_initial_size = value
        return self

    @property
    def pool_acquisition_timeout_seconds(self) -> int:
        return self._pool_acquisition_timeout_seconds

    @pool_acquisition_timeout_seconds.setter
    def pool_acquisition_timeout_seconds(self, value: int):
        self._pool_acquisition_timeout_seconds = value

    def with_pool_acquisition_timeout_seconds(self, value: int) -> 'LocalTxConnectionConfig':
        self._pool_acquisition_timeout_seconds = value
        return self

    @property
    def pool_connection_lifetime_minutes(self) -> int:
        return self._pool_connection_lifetime_minutes

    @pool_connection_lifetime_minutes.setter
    def pool_connection_lifetime_minutes(self, value: int):
        self._pool_connection_lifetime_minutes = value

    def with_pool_connection_lifetime_minutes(self, value: int) -> 'LocalTxConnectionConfig':
        self._pool_connection_lifetime_minutes = value
        return self

    @property
    def pool_transaction_isolation(self) -> str:
        return self._pool_transaction_isolation

    @pool_transaction_isolation.setter
    def pool_transaction_isolation(self, value: str):
        if value not in ['READ_COMMITTED', 'SERIALIZABLE']:
            raise ValueError('Invalid transaction isolation')
        self._pool_transaction_isolation = value

    def with_pool_transaction_isolation(self, value: str) -> 'LocalTxConnectionConfig':
        if value not in ['READ_COMMITTED', 'SERIALIZABLE']:
            raise ValueError('Invalid transaction isolation')
        self._pool_transaction_isolation = value
        return self
```

This Python class provides the same functionality as the Java interface. It has properties for `jdbc_url`, `jdbc_user`, and `jdbc_pass` that can be set using setter methods, which also return a new instance of the class with the updated values. Similarly, there are property-based getter/setter pairs for each of the pool configuration settings (`pool_min_size`, `pool_max_size`, etc.).