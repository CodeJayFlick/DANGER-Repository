class NotConnectedException(Exception):
    """Indicates that the server connection is down.
       When this exception is thrown, the current operation should be aborted.
       At the time this exception is thrown, the user has already been informed 
       of a server error condition."""
    
    def __init__(self, msg: str) -> None:
        super().__init__(msg)

    def __init__(self, msg: str, cause: Exception) -> None:
        super().__init__(msg, cause)
