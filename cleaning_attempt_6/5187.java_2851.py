class PEfException(Exception):
    """An exception class to handle encountering invalid PEF Headers."""

    def __init__(self, message: str) -> None:
        super().__init__(message)

    def __init__(self, cause: Exception) -> None:
        super().__init__(cause)
