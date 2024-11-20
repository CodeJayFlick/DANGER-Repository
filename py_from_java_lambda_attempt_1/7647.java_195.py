Here is the translation of the Java code to Python:
```
import socket

class ServerPortFactory:
    _port_factory = None

    def __init__(self):
        pass  # Construction not permitted

    @classmethod
    def set_base_port(cls, port: int) -> None:
        cls._port_factory = RMIServerPortFactory(port)

    @classmethod
    def get_rmi_registry_port(cls) -> int:
        return cls._port_factory.getRMIRegistryPort() if cls._port_factory else 0

    @classmethod
    def get_rmis_ssl_port(cls) -> int:
        return cls._port_factory.getRMISSLPort() if cls._port_factory else 0

    @classmethod
    def get_stream_port(cls) -> int:
        return cls._port_factory.getStreamPort() if cls._port_factory else 0


class RMIServerPortFactory:
    _default_port = socket.socket(socket.AF_INET, socket.SOCK_STREAM).getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)

    def __init__(self, port: int):
        self.port = port

    def getRMIRegistryPort(self) -> int:
        return self.port

    def getRMISSLPort(self) -> int:
        return self.port + 1  # assume SSL port is one more than RMI registry port

    def getStreamPort(self) -> int:
        return self.port + 2  # assume stream port is two more than RMI registry port
```
Note that I had to make some assumptions about the behavior of `RMIServerPortFactory` since it was not provided in the original Java code. Specifically, I assumed that the SSL-protected RMI port and Stream port are one and two more than the RMI Registry port, respectively. If this is incorrect, please provide additional information or clarify how these ports should be calculated.