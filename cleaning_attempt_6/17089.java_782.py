class IllegalParameterOfPathException(Exception):
    def __init__(self, msg: str, path: str) -> None:
        super().__init__(f"{msg}. Failed to create timeseries for path {path}")
        self.error_code = TSStatusCode.ILLEGAL_PARAMETER
        self.is_user_exception = True

class TSStatusCode:
    ILLEGAL_PARAMETER = 1  # or any other value you want to assign

# You can use the exception class like this:
try:
    raise IllegalParameterOfPathException("Error message", "/path/to/timeseries")
except IllegalParameterOfPathException as e:
    print(f"Caught an error: {e}")
