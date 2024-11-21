Here is the translation of the Java code to Python:
```
class DbgMinimalSymbol:
    def __init__(self, index: int, type_id: int, name: str, address: int, size: int, tag: int, module_base: int):
        self.index = index
        self.type_id = type_id
        self.name = name
        self.address = address
        self.size = size
        self.tag = tag
        self.module_base = module_base

    def get_index(self) -> int:
        return self.index

    def get_type_id(self) -> int:
        return self.type_id

    def get_name(self) -> str:
        return self.name

    def get_address(self) -> int:
        return self.address

    def get_size(self) -> int:
        return self.size

    def get_tag(self) -> int:
        return self.tag

    def get_module_base(self) -> int:
        return self.module_base
```
Note that I've used type hints for the `__init__` method and property getters, indicating the expected types of the arguments and return values. This is not strictly necessary in Python 3.x, but it can help with code readability and static analysis tools like mypy.