from abc import ABCMeta, abstractmethod

class DBAnnotatedField(metaclass=ABCMeta):
    def __init__(self, column: str, indexed=False) -> None:
        self.column = column
        self.indexed = indexed

    @property
    def codec(self) -> type['DBFieldCodec']:
        return DefaultCodec

    class DefaultCodec(ABCMeta):
        @abstractmethod
        def encode(self, value: 'Void') -> dict:
            pass

        @abstractmethod
        def decode(self, data: dict) -> 'Void':
            pass


class Void(metaclass=ABCMeta):
    @abstractmethod
    def __init__(self) -> None:
        pass
