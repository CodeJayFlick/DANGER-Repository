class PcodeExecutionException(Exception):
    def __init__(self, message: str, frame=None, cause=None) -> None:
        super().__init__(message)
        self.frame = frame
        if cause is not None:
            self.__cause__ = cause

    @property
    def frame(self) -> 'PcodeFrame':
        return self._frame

    def __str__(self) -> str:
        return f"PcodeExecutionException: {super().__str__()}"
