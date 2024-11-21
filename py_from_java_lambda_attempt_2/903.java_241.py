Here's the translation of the Java interface `DataModelScript` into a Python class:

```Python
class DataModelScript:
    def __init__(self):
        pass

    def get_name(self) -> str:
        # implement this method as needed
        raise NotImplementedError("Method not implemented")

    def rename(self, script_name: str) -> None:
        # implement this method as needed
        raise NotImplementedError("Method not implemented")

    def populate(self, content_stream: bytes) -> None:
        # implement this method as needed
        raise NotImplementedError("Method not implemented")

    def execute(self, client: object) -> None:
        # implement this method as needed
        raise NotImplementedError("Method not implemented")

    def unlink(self) -> None:
        # implement this method as needed
        raise NotImplementedError("Method not implemented")

    def is_invocable(self) -> bool:
        # implement this method as needed
        raise NotImplementedError("Method not implemented")

    def invoke_main(self, client: object) -> None:
        # implement this method as needed
        raise NotImplementedError("Method not implemented")
```

Note that the Python code does not have direct equivalents for Java's `String`, `WString` and `Pointer`. The equivalent in Python would be using built-in types like `str`, or custom classes if you need more complex data structures.