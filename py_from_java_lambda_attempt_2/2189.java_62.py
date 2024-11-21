Here is the translation of the given Java code into equivalent Python:

```Python
from abc import ABC, abstractmethod


class TargetEnvironment(ABC):
    ARCH_ATTRIBUTE_NAME = "arch"
    DEBUGGER_ATTRIBUTE_NAME = "debugger"
    OS_ATTRIBUTE_NAME = "os"
    ENDIAN_ATTRIBUTE_NAME = "endian"

    @abstractmethod
    def get_architecture(self) -> str:
        pass

    @abstractmethod
    def get_debugger(self) -> str:
        pass

    @abstractmethod
    def get_operating_system(self) -> str:
        pass

    @abstractmethod
    def get_endian(self) -> str:
        pass


class DefaultTargetEnvironment(TargetEnvironment):
    def __init__(self, arch: str = "", debugger: str = "", os: str = "", endian: str = ""):
        self._arch = arch
        self._debugger = debugger
        self._os = os
        self._endian = endian

    def get_architecture(self) -> str:
        return self._arch

    def get_debugger(self) -> str:
        return self._debugger

    def get_operating_system(self) -> str:
        return self._os

    def get_endian(self) -> str:
        return self._endian
```

Note that Python does not have direct equivalent of Java's `@interface` or `@implNote`, so I've used the abstract base class (ABC) and abstract methods to achieve similar functionality.