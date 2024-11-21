class ShutdownException(Exception):
    def __init__(self, message: str = None, cause: Exception = None) -> None:
        if cause is not None:
            super().__init__(str(cause), TSStatusCode.SHUT_DOWN_ERROR)
        elif message is not None:
            super().__init__(message, TSStatusCode.SHUT_DOWN_ERROR)
        else:
            raise ValueError("Either 'message' or 'cause' must be provided")

    @classmethod
    def from_error_code(cls, error_code: int) -> "ShutdownException":
        return cls(f"Error code {error_code}", None, error_code)

TSStatusCode = {
    TSStatusCode.SHUT_DOWN_ERROR: 1,
}
