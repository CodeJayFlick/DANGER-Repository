class NotFoundException(Exception):
    """Exception thrown when an object is not found."""

    def __init__(self, msg="Object was not found."):
        super().__init__(msg)
