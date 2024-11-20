class DeletedException(Exception):
    """Exception thrown when program object being accessed has been deleted."""

    def __init__(self, message="Object has been deleted."):
        super().__init__(message)

class GhidraDeletedException(DeletedException):
    pass
