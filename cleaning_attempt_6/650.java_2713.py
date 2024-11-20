class DbgSetFilterSecondChanceCmdCommand:
    def __init__(self, manager: 'DbgManagerImpl', index: int, cmd: str):
        self.manager = manager
        self.index = index
        self.cmd = cmd

    def invoke(self) -> None:
        control = self.manager.get_control()
        control.set_exception_filter_second_command(self.index, self.cmd)
