import typing as t

class DebuggerTargetObjectIface:
    def __init__(self):
        pass

    @property
    def value(self) -> str:
        raise NotImplementedError("Must be implemented by subclass")
