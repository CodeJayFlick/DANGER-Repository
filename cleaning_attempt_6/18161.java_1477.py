class CacheException(Exception):
    def __init__(self):
        pass  # do nothing

    def __init__(self, message=""):
        super().__init__(message)

    def __init__(self, message="", cause=None):
        if cause:
            super().__init__(message, cause)
        else:
            super().__init__(message)

    def __init__(self, cause=None):
        if cause:
            super().__init__(cause.__str__())
        else:
            pass  # do nothing

    def __init__(self, message="", cause=None, enableSuppression=False, writableStackTrace=True):
        if cause:
            super().__init__(message, cause, enableSuppression, writableStackTrace)
        else:
            super().__init__(message)

# Example usage
try:
    raise CacheException("This is a test exception")
except CacheException as e:
    print(e)
