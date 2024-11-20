# MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class Beast(metaclass=abc.ABCMeta):
    """Beast."""

    def __init__(self, source=None):
        pass

    @abstractmethod
    def copy(self):
        raise NotImplementedError("Must be implemented by subclass")

from prototype import Prototype  # assuming you have a `prototype.py` file with the `Prototype` class defined
