class DWARFE Exception(Exception):
    """Constructs a DWARFException with the specified message."""
    def __init__(self, message: str) -> None:
        super().__init__(message)
