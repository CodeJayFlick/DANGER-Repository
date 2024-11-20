Here is the translation of the Java interface `IDebugHostBaseClass` into a Python class:

```Python
class IDebugHostBaseClass:
    IID_IDEBUG_HOST_BASE_CLASS = "B94D57D2-390B-40f7-B5B4-B6DB897D974B"

    VTIndices = {
        'GET_CONTEXT': 0,
        'ENUMERATE_CHILDREN': 1,
        'GET_SYMBOL_KIND': 2,
        'GET_NAME': 3,
        'GET_TYPE': 4,
        'GET_CONTAINING_MODULE': 5,
        'GET_OFFSET': 6
    }

    def get_context(self):
        pass

    def enumerate_children(self, kind: int, name: str, pp_enum) -> None:
        pass

    def get_symbol_kind(self) -> int:
        pass

    def get_name(self) -> str:
        pass

    def get_type(self) -> None:
        pass

    def get_containing_module(self) -> None:
        pass

    def get_offset(self) -> int:
        pass
```

Note that the Python code does not have direct equivalents for Java's `enum` and `interface`, so I used a dictionary to represent the enum values, and defined each method as an instance method of the class.