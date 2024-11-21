class TsFileRuntimeError(Exception):
    def __init__(self):
        pass

    def __init__(self, message: str = None, cause=None) -> None:
        if message:
            super().__init__(message)
        elif cause:
            super().__init__(cause)

    serialVersionUID = 6455048223316780984
