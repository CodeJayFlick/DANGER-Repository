Here is a translation of the Java interface into equivalent Python code:

```Python
class IDebugHostModule1:
    IID_IDEBUG_HOST_MODULE = "C9BA3E18-D070-4378-BBD0-34613B346E1E"

    class VTIndices1(enum):
        GET_IMAGE_NAME = 0
        GET_BASE_LOCATION = 1
        GET_VERSION = 2
        FIND_TYPE_BY_NAME = 3
        FIND_SYMBOL_BY_RVA = 4
        FIND_SYMBOL_BY_NAME = 5

    def get_image_name(self, allow_path: bool) -> int:
        # implement the method in Python equivalent to GetImageName
        pass

    def get_base_location(self) -> dict:
        # implement the method in Python equivalent to GetBaseLocation
        return {}

    def get_version(self) -> tuple:
        # implement the method in Python equivalent to GetVersion
        return (0, 0)

    def find_type_by_name(self, type_name: str) -> object:
        # implement the method in Python equivalent to FindTypeByName
        pass

    def find_symbol_by_rva(self, rva: int) -> object:
        # implement the method in Python equivalent to FindSymbolByRVA
        pass

    def find_symbol_by_name(self, symbol_name: str) -> object:
        # implement the method in Python equivalent to FindSymbolByName
        pass
```

Please note that this is a direct translation of Java code into Python. The actual implementation will depend on your specific requirements and how you want to handle these methods.