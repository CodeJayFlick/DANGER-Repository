class DbgSetFilterCommand:
    def __init__(self, manager: 'DbgManager', index: int, cmd: str):
        self.manager = manager
        self.index = index
        self.cmd = cmd

    def invoke(self) -> None:
        control = self.manager.get_control()
        control.set_event_filter_command(self.index, self.cmd)
