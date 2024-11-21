class DebuggerModelTerminatingException(Exception):
    def __init__(self, message: str = None, cause: Exception = None) -> None:
        if cause is not None:
            super().__init__(message, cause)
        else:
            super().__init__(message)

if __name__ == "__main__":
    pass
