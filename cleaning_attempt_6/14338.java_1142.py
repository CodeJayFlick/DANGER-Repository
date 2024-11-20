from abc import ABC, abstractmethod

class ConsoleAdministrationSrv(ABC):
    """Console interface for lottery administration."""

    @abstractmethod
    def get_all_submitted_tickets(self) -> None:
        """Get all submitted tickets."""
        pass

    @abstractmethod
    def perform_lottery(self) -> None:
        """Draw lottery numbers."""
        pass

    @abstractmethod
    def reset_lottery(self) -> None:
        """Begin new lottery round."""
        pass
