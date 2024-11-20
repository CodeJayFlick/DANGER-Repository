class UnsupportedFilterDataTypeException(Exception):
    def __init__(self, message=None, cause=None):
        if cause is None:
            super().__init__(message)
        else:
            super().__init__(message, cause)

# Example usage
try:
    # some operation that raises an exception
    raise UnsupportedFilterDataTypeException("Invalid filter data type")
except UnsupportedFilterDataTypeException as e:
    print(f"Caught exception: {e}")
