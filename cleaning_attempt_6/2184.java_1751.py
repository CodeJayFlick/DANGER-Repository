from abc import ABC, abstractmethod


class TargetConsole(ABC):
    CHARSET = 'utf-8'

    class Channel:
        STDOUT = 0
        STDERR = 1

    @abstractmethod
    def write(self, data: bytes) -> None:
        pass
