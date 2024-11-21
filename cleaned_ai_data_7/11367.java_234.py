class AssemblySyntaxException(Exception):
    def __init__(self, message, errors=None):
        super().__init__(message)
        self.errors = set(errors) if errors else None

    @classmethod
    def from_errors(cls, errors):
        return cls("\n".join(str(error) for error in errors), errors)

    def get_errors(self):
        return frozenset(self.errors) if self.errors is not None else None
