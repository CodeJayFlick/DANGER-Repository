class TrainingDivergedException(Exception):
    def __init__(self, message=""):
        super().__init__(message)

    @classmethod
    def from_message(cls, message):
        return cls(message)
