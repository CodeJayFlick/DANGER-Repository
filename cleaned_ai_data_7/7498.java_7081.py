class FGLayout:
    def clone_layout(self):
        # implement this method in your subclass
        pass

    def get_visual_graph(self) -> 'FunctionGraph':
        # implement this method in your subclass
        return None


# Note: In Python, we don't have direct equivalent of Java's interface.
# Instead, you can use abstract base class (ABC) to achieve similar functionality.

from abc import ABC, abstractmethod

class FGLayout(ABC):
    @abstractmethod
    def clone_layout(self):
        pass

    @abstractmethod
    def get_visual_graph(self) -> 'FunctionGraph':
        return None


