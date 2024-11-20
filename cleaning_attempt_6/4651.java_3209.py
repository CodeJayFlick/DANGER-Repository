class DWARFBooleanAttribute:
    TRUE = DWARFBooleanAttribute(True)
    FALSE = DWARFBooleanAttribute(False)

    @classmethod
    def get(cls, b):
        return cls.TRUE if b else cls.FALSE

    def __init__(self, value: bool):
        self.value = value

    def get_value(self) -> bool:
        return self.value

    def __str__(self) -> str:
        return f"DWARFBooleanAttribute: {self.value}"
