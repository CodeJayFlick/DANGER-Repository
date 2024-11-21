Here is the translation of the given Java code into equivalent Python:

```Python
class GhidraClassDB:
    def __init__(self, symbol: 'Symbol', namespace_mgr):
        self.symbol = symbol
        self.namespace_mgr = namespace_mgr

    @property
    def get_symbol(self) -> 'Symbol':
        return self.symbol

    def is_external(self) -> bool:
        return self.symbol.is_external()

    @property
    def name(self) -> str:
        return self.symbol.name

    def set_name(self, name: str, source_type: str, check_for_duplicates: bool = False):
        if not isinstance(name, str):
            raise InvalidInputException("Name must be a string")
        try:
            self.symbol.set_name_and_namespace(name, self.symbol.get_parent_namespace(), source_type, check_for_duplicates)
        except CircularDependencyException as e:
            # can't happen since we are not changing the namespace
            pass

    @property
    def get_id(self) -> int:
        return self.symbol.id

    @property
    def parent_namespace(self):
        return self.symbol.get_parent_namespace()

    @property
    def body(self) -> 'AddressSetView':
        return self.namespace_mgr.get_address_set(self)

    def name_with_path(self, include_namespace_path: bool = False) -> str:
        return self.symbol.name(include_namespace_path)

    def __eq__(self, other):
        if not isinstance(other, GhidraClassDB):
            return NotImplemented
        return self.symbol == other.symbol

    @property
    def parent_namespace_setter(self, namespace: 'Namespace'):
        try:
            self.symbol.set_namespace(namespace)
        except (DuplicateNameException, InvalidInputException, CircularDependencyException) as e:
            raise Exception(f"Failed to set parent namespace. {e}")

    def __str__(self):
        return f"{self.name}  (GhidraClass)"
```

Please note that Python does not support direct translation of Java code into equivalent Python without some modifications and adjustments according to the syntax, semantics and best practices in Python programming language.