class AccessContext:
    def __init__(self):
        pass

    @property
    def operation_id(self) -> str:
        """Provide a unique id for the operation being validated (for correlation purposes)."""
        raise NotImplementedError("operation_id must be implemented")

    @property
    def user(self) -> 'Principal':
        """Provide the user identity."""
        raise NotImplementedError("user must be implemented")


class Principal:
    pass  # You would need to implement this class further based on your requirements.
