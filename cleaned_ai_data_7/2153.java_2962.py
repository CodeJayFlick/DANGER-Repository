class DebuggerModelAccessException(Exception):
    def __init__(self, message=None, cause=None):
        if cause:
            super().__init__(message, cause)
        elif message:
            super().__init__(message)

    @classmethod
    def from_target_object(cls, target_object):
        path = PathUtils().toString(target_object.getPath())
        super().__init__(f"Model path {path} is not accessible")
