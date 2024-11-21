class CodeUnitInsertionException(Exception):
    """Exception thrown when a code unit cannot be created."""

    def __init__(self, msg: str) -> None:
        super().__init__(msg)
