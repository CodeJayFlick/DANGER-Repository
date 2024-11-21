class UndefinedTemplateException(Exception):
    def __init__(self, path: str) -> None:
        message = f"Undefined template name: {path}"
        super().__init__(message)
        self.status_code = TSStatusCode.UNDEFINED_TEMPLATE
        self.is_transient_error = True

TSStatusCode = int  # assuming this is an enum in Java, we can use a Python integer here
