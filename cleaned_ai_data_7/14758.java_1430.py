# MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class Mage(metaclass=abc.ABCMeta):
    """Mage."""

    def __init__(self, source=None):
        pass

    @abstractmethod
    def copy(self):
        raise NotImplementedError("Must be implemented by subclass")
