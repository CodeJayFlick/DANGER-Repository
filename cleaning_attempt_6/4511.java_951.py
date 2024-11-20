class ImproperUseException(Exception):
    """Exception class to be used when API calls are improperly used (i.e., GhidraScript.askProjectFolder() method is being used in Headless mode)."""

    def __init__(self, msg: str) -> None:
        super().__init__(msg)

    def __init__(self, cause: Exception) -> None:
        super().__init__(cause)
