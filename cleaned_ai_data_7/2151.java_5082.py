class DebuggerIllegalArgumentException(Exception):
    def __init__(self, message):
        super().__init__(message)

    def __init__(self, message, cause):
        super().__init__(message)
        self.__cause = cause

    @property
    def cause(self):
        return self.__cause
