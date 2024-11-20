Here is the translation of the Java interface `GhidraServerHandle` into a Python class:

```Python
import rmi  # Assuming you have an RMI module implemented in Python
from abc import ABCMeta, abstractmethod

class GhidraServerHandle(metaclass=ABCMeta):
    INTERFACE_VERSION = 11
    MIN_GHIDRA_VERSION = "9.0"
    DEFAULT_PORT = 13100
    BIND_NAME_PREFIX = "GhidraServer"
    BIND_NAME = f"{BIND_NAME_PREFIX}{MIN_GHIDRA_VERSION}"

    @abstractmethod
    def get_authentication_callbacks(self) -> list:
        pass

    def get_repository_server(self, user: 'Subject', auth_callbacks: list) -> 'RemoteRepositoryServerHandle':
        # Implement the logic for getting a handle to the repository server
        pass

    def check_compatibility(self, server_interface_version: int):
        if server_interface_version != self.INTERFACE_VERSION:
            raise RemoteException("Incompatible interface version")
```

Note that Python does not have built-in support for Remote Method Invocation (RMI) like Java does. Therefore, we assume you have implemented an RMI module in Python and import it as `rmi`. The abstract methods are marked with the `@abstractmethod` decorator to indicate they must be implemented by any subclass.

Also note that I did not implement the actual logic for getting a handle to the repository server or checking compatibility. You would need to fill those out based on your specific requirements.