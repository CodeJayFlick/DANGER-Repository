class QueryFilterOptimizationException(Exception):
    def __init__(self, message=""):
        if not message:
            message = "Query filter optimization exception"
        super().__init__(message)

    @classmethod
    def from_cause(cls, cause):
        return cls(str(cause), cause)
