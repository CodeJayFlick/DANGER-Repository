class OsgiException(Exception):
    """Wrapper for exceptions originating with an OSGi operation."""
    
    def __init__(self, message: str = None, cause: Exception = None) -> None:
        if cause is not None:
            super().__init__(message, cause)
        else:
            super().__init__(message)

# Example usage
try:
    # Your code here that might raise an exception
except OsgiException as e:
    print(f"OSGiException: {e}")
