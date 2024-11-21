class AddressFormatException(Exception):
    """An exception that gets raised when a string cannot be parsed as an address."""
    
    def __init__(self, message="Cannot parse string into address.") -> None:
        super().__init__(message)
