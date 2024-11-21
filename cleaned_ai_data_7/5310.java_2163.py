class ExporterException(Exception):
    def __init__(self, msg=None, cause=None):
        if msg:
            super().__init__(msg)
        elif cause:
            super().__init__(cause)

# Example usage
try:
    # some code that might raise an exception
except Exception as e:
    raise ExporterException("Custom error message", e) from None

