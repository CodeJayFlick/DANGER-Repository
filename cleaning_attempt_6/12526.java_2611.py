class CircularDependencyException(Exception):
    def __init__(self, message="Reference is invalid."):
        super().__init__(message)
