class CliAbstractTableRow:
    def __init__(self):
        pass
    
    def get_representation(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")
    
    def get_short_representation(self, stream: 'CliStreamMetadata' = None) -> str:
        return self.get_representation()
    
    def get_representation(self, stream: 'CliStreamMetadata' = None) -> str:
        return self.get_representation()

class CliStreamMetadata:
    pass

from abc import ABCMeta, abstractmethod
metaclass = ABCMeta

class CliRepresentable(metaclass=ABCMeta):
    @abstractmethod
    def get_representation(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")
