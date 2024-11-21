from abc import ABCMeta, abstractmethod


class AbstractGColumnRenderer(metaclass=ABCMeta):
    """A convenience base class that combines GTableCellRenderer with GColumnRenderer interface."""
    
    @abstractmethod
    def __init__(self) -> None:
        pass

    # nothing yet; convenience interface
