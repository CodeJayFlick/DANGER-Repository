class SymbolTable:
    def __init__(self):
        pass

    # Create a label symbol with the given name associated to the given address.
    # The symbol will be global and be of type 'CODE'. Label symbols do not have to have unique names.
    def create_label(self, addr: Address, name: str) -> Symbol:
        raise NotImplementedError("Method must be implemented by subclass")

    # Create a label symbol with the given name associated to the given address
    # and namespace. The symbol will be of type 'CODE'. If this is the first symbol defined for the address it becomes the primary.
    def create_label(self, addr: Address, name: str, namespace: Namespace) -> Symbol:
        raise NotImplementedError("Method must be implemented by subclass")

    # Remove the specified symbol from the symbol table. 
    # If removing any non-function symbol the behavior will be the same as invoking 'Symbol.delete()' on the symbol.
    def remove_symbol(self, sym: Symbol):
        raise NotImplementedError("Method must be implemented by subclass")

    # Get the symbol for the given symbol ID.
    def get_symbol(self, symbol_id: int) -> Symbol:
        raise NotImplementedError("Method must be implemented by subclass")

    # Get the symbol with the given name and address. 
    # Note that this results in a single Symbol because of an additional restriction
    # that allows only one symbol with a given name at the same address.
    def get_global_symbol(self, name: str, addr: Address) -> Symbol:
        raise NotImplementedError("Method must be implemented by subclass")

    # Get all global symbols with the given name. 
    # Note that this method will not return default thunks (i.e., thunk function symbol with default source type).
    def get_global_symbols(self, name: str) -> List[Symbol]:
        raise NotImplementedError("Method must be implemented by subclass")

    # Returns a list of all symbols in the given namespace.
    # 
    # NOTE: The resulting iterator will not return default thunks (i.e., thunk function symbol with default source type).
    def get_symbols(self, namespace: Namespace) -> List[Symbol]:
        raise NotImplementedError("Method must be implemented by subclass")

    # Returns a list of all symbols in the given namespace.
    # 
    # NOTE: The resulting iterator will not return default thunks (i.e., thunk function symbol with default source type).
    def get_symbols(self, namespace_id: int) -> List[Symbol]:
        raise NotImplementedError("Method must be implemented by subclass")

    # Returns true if there exists a symbol at the given address.
    def has_symbol(self, addr: Address) -> bool:
        raise NotImplementedError("Method must be implemented by subclass")

    # Get iterator over all defined symbols in no particular order.
    def get_defined_symbols(self) -> List[Symbol]:
        raise NotImplementedError("Method must be implemented by subclass")

    # Returns an iterator over all primary symbols. 
    # NOTE: The resulting iterator will not return default thunks (i.e., thunk function symbol with default source type).
    def get_primary_symbol_iterator(self, forward: bool = True) -> List[Symbol]:
        raise NotImplementedError("Method must be implemented by subclass")

    # Get an iterator over all symbols.
    # 
    # NOTE: The resulting iterator will not return default thunks (i.e., thunk function symbol with default source type).
    def get_symbol_iterator(self, forward: bool = True) -> List[Symbol]:
        raise NotImplementedError("Method must be implemented by subclass")

    # Get an iterator over all symbols at addresses in the given address set.
    # 
    # NOTE: The resulting iterator will not return default thunks (i.e., thunk function symbol with default source type).
    def get_symbol_iterator(self, asv: AddressSetView, forward: bool = True) -> List[Symbol]:
        raise NotImplementedError("Method must be implemented by subclass")

    # Set the given address to be an external entry point.
    def add_external_entry_point(self, addr: Address):
        raise NotImplementedError("Method must be implemented by subclass")

    # Remove the given address as an external entry point.
    def remove_external_entry_point(self, addr: Address):
        raise NotImplementedError("Method must be implemented by subclass")

    # Returns true if the given address has been set as an external entry point.
    def is_external_entry_point(self, addr: Address) -> bool:
        raise NotImplementedError("Method must be implemented by subclass")

    # Get forward/back iterator over addresses that are entry points.
    def get_external_entry_points(self) -> List[Address]:
        raise NotImplementedError("Method must be implemented by subclass")

    # Get the label history objects for the given address. 
    # The history object records changes made to labels at some address.
    def get_label_history(self, addr: Address) -> List[LabelHistory]:
        raise NotImplementedError("Method must be implemented by subclass")

    # Create a class namespace in the given parent namespace.
    def create_class(self, parent: Namespace, name: str, source_type: SourceType) -> GhidraClass:
        raise NotImplementedError("Method must be implemented by subclass")

    # Convert the given namespace to a class namespace
    def convert_namespace_to_class(self, namespace: Namespace) -> GhidraClass:
        raise NotImplementedError("Method must be implemented by subclass")
