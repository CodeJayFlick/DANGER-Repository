import ghidra_framework as gfh

class ProjectInitializer:
    def run(self):
        # Register "ghidra" URL protocol Handler
        gfh.protocol.ghidra.Handler.register_handler()

    def get_name(self):
        return "Project Module"

# Note: In Python, we don't have a direct equivalent of Java's interface or abstract class.
# Instead, you can use an abstract base class (ABC) from the abc module to define an abstract method.
from abc import ABC, abstractmethod

class ProjectInitializer(ABC):
    @abstractmethod
    def run(self):
        pass

    @property
    @abstractmethod
    def name(self):
        return "Project Module"
