class InterpreterConnection:
    def __init__(self):
        pass

    def get_title(self) -> str:
        """Gets the title of the interpreter."""
        return ""

    def get_icon(self) -> bytes:
        """Gets the icon associated with the interpreter. Null if default icon is desired."""
        return None  # or b"" for a null byte string

    def get_completions(self, cmd: str) -> list:
        """Gets a list of code completions for the given command."""
        return []
