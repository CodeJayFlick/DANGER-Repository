class InvalidDataTypeException(Exception):
    def __init__(self, message="Invalid data type error.", dt=None):
        if dt:
            super().__init__(f"Invalid data type error for {dt.get_display_name()}.")
        else:
            super().__init__(message)

    @classmethod
    def from_message(cls, message: str) -> 'InvalidDataTypeException':
        return cls(message)
