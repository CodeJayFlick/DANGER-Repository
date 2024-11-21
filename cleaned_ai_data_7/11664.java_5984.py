class SleighError(Exception):
    def __init__(self, message: str, location: 'Location') -> None:
        super().__init__(message)
        self.location = location
