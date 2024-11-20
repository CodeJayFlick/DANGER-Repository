class FolderNotEmptyException(Exception):
    """Raised when an attempt is made to remove a folder which is not empty."""
    
    def __init__(self, msg: str) -> None:
        super().__init__(msg)
