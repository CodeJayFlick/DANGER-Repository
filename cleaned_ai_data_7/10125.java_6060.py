class LockException(Exception):
    """Indicates a failure to obtain a required lock."""
    
    def __init__(self, message="Operation requires exclusive access to object.") -> None:
        super().__init__(message)
