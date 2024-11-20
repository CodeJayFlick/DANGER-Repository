class SymbolType:
    def __init__(self, name: str, is_namespace: bool, value: int):
        self.name = name
        self.is_namespace = is_namespace
        self.value = value

LABEL = SymbolType("Label", False, 0)
CODE = LABEL
LIBRARY = SymbolType("Library", True, 1)

class Namespace:
    def __init__(self, id: str):
        self.id = id

GLOBAL_NAMESPACE_ID = "GLOBAL_NAMESPACE_ID"
NAMESPACES = [Namespace(GLOBAL_NAMESPACE_ID)]

CLASS = SymbolType("Class", True, 4)
FUNCTION = SymbolType("Function", True, 5)

class Address:
    def __init__(self, is_memory_address: bool):
        self.is_memory_address = is_memory_address

class Program:
    pass

def get_symbol_type(id: int) -> 'SymbolType':
    if id == -1:
        return GLOBAL
    elif id < 0 or id >= len(types):
        return None
    else:
        return types[id]

types = [LABEL, LIBRARY, CLASS, FUNCTION]
GLOBAL = SymbolType("Global", True, -1)

def is_valid_parent(program: Program, parent: Namespace, symbol_addr: Address, is_external_symbol: bool) -> bool:
    if isinstance(parent, Function):
        return program == parent.get_program()
    else:
        return False

def is_valid_address(program: Program, symbol_address: Address) -> bool:
    if isinstance(symbol_address, Address):
        return True
    else:
        return False

def is_valid_source_type(source_type: str, symbol_address: Address) -> bool:
    if source_type == "DEFAULT":
        return False
    elif isinstance(symbol_address, Address):
        return True
    else:
        return False

class SourceType:
    def __init__(self, value: str):
        self.value = value

def allows_duplicates(self) -> bool:
    return False

def is_namespace(self) -> bool:
    return self.is_namespace

def to_string(self) -> str:
    return self.name
