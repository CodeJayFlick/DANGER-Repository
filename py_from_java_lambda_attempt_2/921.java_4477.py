Here is the translation of the given Java interface into a Python class:

```Python
class DebugHostBase:
    def __init__(self):
        pass

    def get_context(self) -> 'DebugHostContext':
        raise NotImplementedError("Method not implemented")

    def enumerate_children(self, symbol_module: str, name: str) -> iter:
        raise NotImplementedError("Method not implemented")

    def get_symbol_kind(self) -> str:
        raise NotImplementedError("Method not implemented")

    def get_name(self) -> str:
        raise NotImplementedError("Method not implemented")

    def get_type(self) -> 'DebugHostType1':
        raise NotImplementedError("Method not implemented")

    def get_containing_module(self) -> 'DebugHostModule1':
        raise NotImplementedError("Method not implemented")

    def get_offset(self) -> int:
        raise NotImplementedError("Method not implemented")

    def get_jna_data(self) -> object:
        raise NotImplementedError("Method not implemented")
```

Note that this is a direct translation of the Java interface into Python, and does not include any actual implementation. The `get_context`, `enumerate_children`, etc., methods are declared as abstract in Python using the `raise NotImplementedError` statement.