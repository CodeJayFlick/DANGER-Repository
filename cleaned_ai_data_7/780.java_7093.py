class DbgModelTargetRoot:
    def set_default_connector(self, default_connector):
        pass  # method implemented by subclasses

# Note: In Python, we don't have interfaces like in Java.
# Instead, we use abstract base classes (ABCs) or protocols to define the interface.
# Here's an example of how you could implement this using ABC:
from abc import ABC, abstractmethod

class DbgModelTargetRoot(ABC):
    @abstractmethod
    def set_default_connector(self, default_connector):
        pass  # method implemented by subclasses
