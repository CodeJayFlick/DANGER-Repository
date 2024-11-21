class FileInUseException(Exception):
    """Indicates that there was contention for a file which is in-use.
       This can be caused for various reasons including a file lock of some kind."""
    
    def __init__(self, msg: str) -> None:
        super().__init__(msg)

    def __init__(self, msg: str, cause: Exception) -> None:
        super().__init__(msg, cause)
