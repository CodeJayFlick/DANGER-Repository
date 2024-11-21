from abc import ABCMeta, abstractmethod


class StartupCheck(metaclass=ABCMeta):
    @abstractmethod
    def execute(self) -> None:
        """Run some tests to check whether system is safe to be started."""
