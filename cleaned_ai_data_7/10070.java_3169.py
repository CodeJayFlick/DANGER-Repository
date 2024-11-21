class ServerInfo:
    def __init__(self, host: str, port_number: int):
        self.host = host
        self.port_number = port_number

    @property
    def server_name(self) -> str:
        return self.host

    @property
    def port_number(self) -> int:
        return self.port_number

    def __eq__(self, other):
        if not isinstance(other, ServerInfo):
            return False
        return self.host == other.host and self.port_number == other.port_number

    def __str__(self):
        return f"{self.host}:{self.port_number}"

    def __hash__(self):
        return hash((self.host, self.port_number))
