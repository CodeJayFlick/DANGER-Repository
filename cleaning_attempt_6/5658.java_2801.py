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
