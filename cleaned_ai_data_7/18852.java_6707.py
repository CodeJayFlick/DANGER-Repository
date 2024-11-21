from abc import ABC, abstractmethod
import typing as t

class DeltaLakeTable(ABC):
    @abstractmethod
    def get_metadata_location_history(self) -> t.List[str]:
        pass

    @abstractmethod
    def get_checkpoint_location_history(self) -> t.List[str]:
        pass

    @abstractmethod
    def get_last_checkpoint(self) -> str:
        pass
