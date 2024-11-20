class DbgCommandDoneEvent:
    def __init__(self):
        pass

    def __init__(self, cmd: 'DbgCommand') -> None:
        super().__init__()
        self.cmd = cmd

    @property
    def new_state(self) -> str:
        return "STOPPED"

    @property
    def command(self) -> 'DbgCommand':
        return self.cmd


class DbgCommand:
    pass


class DbgState:
    STOPPED = "STOPPED"
