class BusyToolException(Exception):
    """Exception thrown if an operation cannot be done because the tool has background tasks running."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
