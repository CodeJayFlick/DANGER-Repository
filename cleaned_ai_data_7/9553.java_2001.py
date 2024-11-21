class TextFieldElement:
    def __init__(self, attributed_string: str, row: int, column: int):
        super().__init__(attributed_string, row, column)

    def substring(self, start: int, end: int) -> 'TextFieldElement':
        as_ = attributed_string[start:end]
        if as_ == attributed_string:
            return self
        return TextFieldElement(as_, row, column + start)

    def replace_all(self, targets: list[str], replacement: str) -> 'TextFieldElement':
        return TextFieldElement(attributed_string.replace(targets[0], replacement), row, column)
