class InsufficientBytesException(Exception):
    """An exception indicating that there were not enough consecutive bytes available to fully parse an instruction."""
    
    def __init__(self, message="Not enough bytes available to parse a legal instruction"):
        super().__init__(message)
