# Enum for address types with unique colors
class AddressType(Enum):
    FUNCTION = ("Function",)
    UNINITIALIZED = ("Uninitialized",)
    EXTERNAL_REF = ("External Reference",)
    INSTRUCTION = ("Instruction",)
    DATA = ("Data",)
    UNDEFINED = ("Undefined",)

    def __init__(self, description: str) -> None:
        self.description = description

    @property
    def description(self) -> str:
        return self.description
