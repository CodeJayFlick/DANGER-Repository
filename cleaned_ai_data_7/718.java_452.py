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
