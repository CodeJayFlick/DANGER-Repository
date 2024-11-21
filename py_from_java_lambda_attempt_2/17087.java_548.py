Here's the equivalent Python code:

```Python
class DifferentTemplateException(Exception):
    def __init__(self, path: str, template_name: str) -> None:
        message = f"The template on {path} is different from {template_name}"
        super().__init__(message)
```

Note that in Python, we don't need to specify the package name or import any specific modules. The `Exception` class is built-in and can be used directly.