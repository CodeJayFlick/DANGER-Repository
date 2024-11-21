class ModelNotFoundException(Exception):
    def __init__(self, message=""):
        if not message:
            message = "Model Not Found"
        super().__init__(message)

    @classmethod
    def from_message(cls, message):
        return cls(message)
