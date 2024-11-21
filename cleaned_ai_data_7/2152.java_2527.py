class DebuggerMemoryAccessException(Exception):
    def __init__(self, message, cause=None):
        super().__init__(message)
        self.cause = cause


if __name__ == "__main__":
    try:
        # Example usage: Raise an exception with a custom error message and optional inner exception.
        raise DebuggerMemoryAccessException("Unknown condition preventing memory access", ValueError("This is the underlying issue"))
    except DebuggerMemoryAccessException as e:
        print(f"Error occurred: {e}")
