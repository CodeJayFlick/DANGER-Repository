class DbgEventFilterImpl:
    def __init__(self, index: int, text: str, cmd: str, arg: str, execution_option: int, continue_option: int):
        self.index = index
        self.text = text
        self.cmd = cmd
        self.arg = arg if arg else "N/A"
        self.execution_option = execution_option
        self.continue_option = continue_option

    def get_index(self) -> int:
        return self.index

    def get_name(self) -> str:
        return self.text

    def get_arg(self) -> str:
        return self.arg if self.arg else "N/A"

    def get_cmd(self) -> str:
        return self.cmd

    def get_execution_option(self) -> int:
        return self.execution_option

    def set_execution_option(self, execution_option: int):
        self.execution_option = execution_option

    def get_continue_option(self) -> int:
        return self.continue_option

    def set_continue_option(self, continue_option: int):
        self.continue_option = continue_option
