class TemplateIsInUseException(Exception):
    def __init__(self, path: str) -> None:
        super().__init__(f"Template is in use on {path}")
