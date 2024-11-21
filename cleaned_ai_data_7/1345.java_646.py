import abc

class GdbGetVarCommand:
    def __init__(self, manager: 'GdbManagerImpl', var_name: str):
        self.manager = manager
        self.var_name = var_name

    @abc.abstractmethod
    def encode(self) -> str:
        return f"-gdb-show {self.var_name}"

    def complete(self, pending_command: object) -> str | None:
        if isinstance(pending_command, GdbCommandDoneEvent):
            return getattr(pending_command, 'maybe_value', None)
