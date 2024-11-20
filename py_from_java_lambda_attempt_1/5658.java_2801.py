Here's a translation of the Java interface into equivalent Python classes:

```Python
from abc import ABCMeta, abstractmethod
import itertools

class CryptoSession(metaclass=ABCMeta):
    @abstractmethod
    def get_passwords_for(self, fsrl: 'FSRL', prompt: str) -> iter:
        pass

    @abstractmethod
    def add_successful_password(self, fsrl: 'FSRL', password_value: 'PasswordValue') -> None:
        pass

    @abstractmethod
    def is_closed(self) -> bool:
        pass

    @abstractmethod
    def close(self) -> None:
        pass


class PasswordValue:
    # No equivalent Java code provided for this class, so it's not translated.
    pass


class FSRL:
    # No equivalent Java code provided for this class, so it's not translated.
    pass
```

This Python translation does not include the actual implementation of these classes. It only defines their structure and methods based on the given Java interface.

Note: The `@abstractmethod` decorator is used to define abstract methods in a Python class.