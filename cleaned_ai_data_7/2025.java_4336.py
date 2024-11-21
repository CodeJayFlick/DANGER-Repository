from abc import ABC, abstractmethod


class JdiModelTargetEnvironment(ABC):
    def refresh_internal(self):
        pass  # No equivalent in Python for this method

    @abstractmethod
    def get_architecture(self) -> str:
        raise NotImplementedError("Method not implemented")

    @abstractmethod
    def get_debugger(self) -> str:
        raise NotImplementedError("Method not implemented")

    @abstractmethod
    def get_operating_system(self) -> str:
        raise NotImplementedError("Method not implemented")
