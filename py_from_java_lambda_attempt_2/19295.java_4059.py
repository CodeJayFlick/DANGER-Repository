Here is the translation of the Java code to Python:
```python
class EnumParser:
    def __init__(self, enum_type: type, allowed_values=None):
        self.enum_type = enum_type
        self.allowed_values = allowed_values
        self.type = str(enum_type)

    @property
    def allowed_values(self) -> str | None:
        if len(list(self.enum_type.__members__.values())) <= 12:
            values = [e.name().lower().replace("_", " ") for e in self.enum_type.__members__.values()]
            return ", ".join(values)
        else:
            return None

    def convert(self, s: str) -> type | None:
        try:
            return getattr(self.enum_type, s.upper().replace(" ", "_"))
        except AttributeError as e:
            Skript.error(f"'{s}' is not a valid value for {self.type}{'' if self.allowed_values else f". Allowed values are: {self.allowed_values}"")
            return None

    def __str__(self) -> str:
        return f"EnumParser{{enum={self.enum_type}, allowed_values={self.allowed_values}, type={self.type}}}"
```
Note that I've used the `type` hint to indicate the expected types of variables and function parameters, but Python is dynamically typed so you don't need to specify these hints in your actual code.