class DebuggerInterpreterConnection:
    def __init__(self):
        pass

    def set_pinned(self, pinned: bool) -> None:
        pass  # TO DO: implement the method

    def is_pinned(self) -> bool:
        return False  # TO DO: implement the method

    def get_target_console(self) -> object:
        raise NotImplementedError("Method not implemented")

    def get_interpreter_console(self) -> object:
        raise NotImplementedError("Method not implemented")
