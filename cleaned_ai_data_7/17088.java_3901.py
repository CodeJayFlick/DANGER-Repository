class DuplicatedTemplateException(Exception):
    def __init__(self, path: str) -> None:
        message = f"Failed to create duplicated template for path {path}"
        super().__init__(message)
        self.status_code = TSStatusCode.DUPLICATED_TEMPLATE
        self.is_client_error = True

TSStatusCode = int  # assuming this is an enum in the original code, we can just use a Python integer


# example usage:
try:
    raise DuplicatedTemplateException("path/to/template")
except Exception as e:
    print(f"Error: {e}")
