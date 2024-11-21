class FormatArgument:
    def __init__(self, length_modifier: str, conversion_specifier: str):
        self.length_modifier = length_modifier
        self.conversion_specifier = conversion_specifier

    @property
    def length_modifier(self) -> str:
        return self.length_modifier

    @property
    def conversion_specifier(self) -> str:
        return self.conversion_specifier

    def __str__(self):
        return f"[{self.length_modifier}, {self.conversion_specifier}]"
