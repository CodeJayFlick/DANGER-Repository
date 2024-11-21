class RepeatableComment:
    def __init__(self):
        self.comment = ""

    def get_comment(self) -> str:
        """Get the text of the repeatable comment."""
        return self.comment

    def set_comment(self, comment: str) -> None:
        """Set the text of this repeatable comment."""
        self.comment = comment
