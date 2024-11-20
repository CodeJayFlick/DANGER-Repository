from abc import ABC, abstractmethod
import concurrent.futures

class DbgModelTargetConnector(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def get_display(self) -> str:
        """Get the display name of this target connector."""
        raise NotImplementedError("Must be implemented by subclass")

    @abstractmethod
    async def set_active(self) -> concurrent.futures.Future[None]:
        """Set the active state of this target connector."""
        raise NotImplementedError("Must be implemented by subclass")

    @abstractmethod
    def get_parameters(self) -> dict:
        """Get the parameters for this target connector."""
        raise NotImplementedError("Must be implemented by subclass")

    @abstractmethod
    async def launch(self, args: dict) -> concurrent.futures.Future[None]:
        """Launch this target connector with given arguments."""
        raise NotImplementedError("Must be implemented by subclass")
