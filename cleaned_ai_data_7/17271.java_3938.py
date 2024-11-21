class ShowLockInfoOperator:
    def __init__(self, token_int_type: int, partial_path: 'PartialPath') -> None:
        super().__init__(token_int_type)
        self.path = partial_path

    @property
    def path(self) -> 'PartialPath':
        return self._path

class PartialPath:
    pass  # This is a placeholder for the Python equivalent of Java's PartialPath class, which you would need to implement separately in Python.
