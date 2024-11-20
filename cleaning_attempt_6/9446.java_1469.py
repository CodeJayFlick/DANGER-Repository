class IntEditor:
    def __init__(self):
        pass

    def set_as_text(self, text: str) -> None:
        try:
            self.set_value(int(text))
        except ValueError as e:
            raise ValueError(f"Invalid integer: {text}") from e
