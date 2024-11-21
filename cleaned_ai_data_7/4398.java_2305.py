class ProxySymbol:
    def __init__(self, id: int, address):
        self.id = id
        self.address = address

    def __eq__(self, other):
        if not isinstance(other, Symbol):
            return False
        if other == self:
            return True
        # this class is only ever equal if the id matches
        s = other
        if self.get_id() == s.get_id():
            return True
        return False

    def __hash__(self):
        return hash(self.id)

    def get_id(self) -> int:
        return self.id

    def get_address(self) -> Address:
        return self.address

    # The following methods are placeholders for unsupported operations in the original Java code.
    def get_symbol_type(self):
        raise NotImplementedError()

    def get_program_location(self):
        raise NotImplementedError()

    def is_external(self):
        raise NotImplementedError()

    def get_object(self):
        raise NotImplementedError()

    def is_primary(self):
        raise NotImplementedError()

    def is_valid_parent(self, namespace: Namespace) -> bool:
        raise NotImplementedError()

    def get_name(self) -> str:
        raise NotImplementedError()

    def get_path(self) -> list[str]:
        raise NotImplementedError()

    def get_program(self) -> Program:
        raise NotImplementedError()

    def get_name_with_namespace(self, include_namespace: bool) -> str:
        raise NotImplementedError()

    def get_parent_namespace(self) -> Namespace:
        raise NotImplementedError()

    def get_parent_symbol(self) -> Symbol:
        raise NotImplementedError()

    def is_descendant(self, namespace: Namespace) -> bool:
        raise NotImplementedError()

    def get_reference_count(self):
        raise NotImplementedError()

    def has_multiple_references(self) -> bool:
        raise NotImplementedError()

    def has_references(self) -> bool:
        raise NotImplementedError()

    def get_references(self) -> list[Reference]:
        raise NotImplementedError()

    def set_name(self, new_name: str, source_type: SourceType):
        raise NotImplementedError()

    def set_namespace(self, namespace: Namespace):
        raise NotImplementedError()

    def set_name_and_namespace(self, new_name: str, namespace: Namespace, source_type: SourceType):
        raise NotImplementedError()

    def delete(self) -> bool:
        raise NotImplementedError()

    def is_pinned(self) -> bool:
        raise NotImplementedError()

    def set_pinned(self, pinned: bool):
        raise NotImplementedError()

    def is_dynamic(self) -> bool:
        raise NotImplementedError()

    def set_primary(self) -> bool:
        raise NotImplementedError()

    def is_external_entry_point(self) -> bool:
        raise NotImplementedError()

    def is_global(self) -> bool:
        raise NotImplementedError()

    def set_source(self, source_type: SourceType):
        raise NotImplementedError()

    def get_source(self) -> SourceType:
        raise NotImplementedError()

    def is_deleted(self) -> bool:
        raise NotImplementedError()

    def __str__(self):
        return f"{type(self).__name__}[id={self.id}, address={self.address}]"
