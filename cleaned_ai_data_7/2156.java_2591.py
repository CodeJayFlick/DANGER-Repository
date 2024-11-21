class DebuggerModelTypeException(Exception):
    @classmethod
    def type_required(cls, got, path, expected_type):
        return cls(f"Path {path} does not refer to a {expected_type.__name__}. Got {got} (of {type(got).__name__})")

    @classmethod
    def link_forbidden(cls, target_object, path):
        return cls(f"Path {path} is a link to {target_object.path}, but following links was forbidden")

    def __init__(self, message):
        super().__init__(message)

    def __init__(self, message, cause):
        super().__init__(message, cause)
