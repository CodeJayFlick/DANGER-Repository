class DifferentTemplateException(Exception):
    def __init__(self, path: str, template_name: str) -> None:
        message = f"The template on {path} is different from {template_name}"
        super().__init__(message)
