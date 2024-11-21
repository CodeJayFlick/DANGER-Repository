class GadpIllegalStateException(Exception):
    def __init__(self, message):
        super().__init__(message)

    def __init__(self, message, cause):
        super().__init__(message)
        self.__cause__ = cause

# Example usage:
try:
    # Some code that might raise an exception
except GadpIllegalStateException as e:
    print(f"Caught {e}")
