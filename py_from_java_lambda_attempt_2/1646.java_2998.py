Here is the translation of the given Java interface into a Python class:

```Python
from abc import ABC, abstractmethod


class LldbModelTargetEnvironment(ABC):
    def refresh_internal(self):
        pass  # This method does not have any equivalent in Python.

    @abstractmethod
    def get_architecture(self) -> str:
        """Get the architecture."""
        raise NotImplementedError

    @abstractmethod
    def get_debugger(self) -> str:
        """Get the debugger."""
        raise NotImplementedError

    @abstractmethod
    def get_operating_system(self) -> str:
        """Get the operating system."""
        raise NotImplementedError


class LldbModelTargetObject(ABC):
    pass  # This class does not have any equivalent in Python.

```

Please note that this translation is based on my understanding of Java and its interface. If there are any specific requirements or constraints, please let me know so I can adjust the code accordingly.