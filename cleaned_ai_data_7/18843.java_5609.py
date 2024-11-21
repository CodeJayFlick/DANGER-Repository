class NessieNotFoundException(Exception):
    """Base class for all exceptions that are represented by the HTTP 404 status code (Not Found)."""

    def __init__(self, message: str = None, cause: Exception = None) -> None:
        if message is not None and cause is not None:
            super().__init__(message, 404, "Not Found", cause)
        elif message is not None:
            super().__init__(message, 404, "Not Found")
        else:
            raise ValueError("At least one of `message` or `cause` must be provided")

    def __init__(self, error: 'NessieError') -> None:
        super().__init__(error)
