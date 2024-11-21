class IllegalFieldAccessException(Exception):
    """An illegal access has been performed on a field."""

    def __init__(self, message="Illegal field access"):
        super().__init__(message)
