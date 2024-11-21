class IllegalPanelStateException(Exception):
    """Allows unexpected IOExceptions and other errors to be thrown during Wizard panel transitions"""
    def __init__(self, cause: Exception) -> None:
        super().__init__(cause)
