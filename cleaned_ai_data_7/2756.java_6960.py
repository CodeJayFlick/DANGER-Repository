class AccessPcodeExecutionException(Exception):
    def __init__(self, message: str = None, frame=None, cause: Exception = None) -> None:
        if cause is not None:
            super().__init__(message, cause)
        elif frame is not None and message is not None:
            super().__init__(f"{message} (frame={frame})")
        else:
            super().__init__(message)

    def __str__(self) -> str:
        return self.args[0]
