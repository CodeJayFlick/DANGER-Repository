Here is the translation of the Java code to Python:
```
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
```
Note that I used the `Enum` class from Python's built-in `enum` module to create an enum. The rest of the code is straightforward translation from Java to Python.

Also, in Python, we don't need a separate constructor method like Java does; instead, we define the attribute (`description`) inside the class definition and use the `__init__` special method to initialize it when creating instances of the enum.