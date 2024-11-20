Here is the translation of the given Java code into Python:

```Python
class SymbolServerRow:
    class LocationStatus(enum.Enum):
        UNKNOWN = 0
        VALID = 1
        INVALID = 2

    def __init__(self, symbol_server: 'SymbolServer'):
        self.symbol_server = symbol_server
        self.status = SymbolServerRow.LocationStatus.UNKNOWN

    @property
    def symbol_server(self) -> 'SymbolServer':
        return self._symbol_server

    @symbol_server.setter
    def symbol_server(self, value: 'SymbolServer') -> None:
        self._symbol_server = value

    def is_enabled(self) -> bool:
        return not isinstance(self.symbol_server, DisabledSymbolServer)

    def set_enabled(self, enabled: bool) -> None:
        if self.is_enabled() == enabled:
            return
        if enabled:
            dss = DisabledSymbolServer(self.symbol_server)
            self.symbol_server = dss.get_symbol_server()
        else:
            self.symbol_server = DisabledSymbolServer(self.symbol_server)

    @property
    def status(self) -> 'LocationStatus':
        return self._status

    @status.setter
    def status(self, value: 'LocationStatus') -> None:
        self._status = value

    def __str__(self) -> str:
        return f"SymbolServerRow: [status: {self.status.name}, server: {self.symbol_server}]"
```

Note that Python does not have an exact equivalent to Java's `enum` type. Instead, we use the built-in `enum` module from Python 3.4 onwards or the `Enum` class from the `aenum` library for earlier versions of Python.