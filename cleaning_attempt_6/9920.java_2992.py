from abc import ABC, abstractmethod

class GTreeSelectionListener(ABC):
    @abstractmethod
    def value_changed(self, e):
        """Called whenever the value of the selection changes.
        
        :param e: The event that characterizes the change."""
