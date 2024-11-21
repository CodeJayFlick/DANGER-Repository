class Symbol:
    def __init__(self):
        pass

    def get_address(self) -> 'Address':
        raise NotImplementedError("Method not implemented")

    def get_name(self) -> str:
        raise NotImplementedError("Method not implemented")

    def get_path(self) -> list[str]:
        raise NotImplementedError("Method not implemented")

    def get_program(self) -> 'Program' | None:
        raise NotImplementedError("Method not implemented")

    def get_name_with_namespace(self, include_namespace: bool = False) -> str:
        raise NotImplementedError("Method not implemented")

    def get_parent_namespace(self) -> 'Namespace':
        raise NotImplementedError("Method not implemented")

    def is_descendant(self, namespace: 'Namespace') -> bool:
        raise NotImplementedError("Method not implemented")

    def is_valid_parent(self, parent: 'Namespace') -> bool:
        raise NotImplementedError("Method not implemented")

    def get_symbol_type(self) -> int:
        raise NotImplementedError("Method not implemented")

    def get_reference_count(self) -> int:
        raise NotImplementedError("Method not implemented")

    def has_multiple_references(self) -> bool:
        raise NotImplementedError("Method not implemented")

    def has_references(self) -> bool:
        raise NotImplementedError("Method not implemented")

    def get_references(self, monitor: 'TaskMonitor' = None) -> list['Reference']:
        raise NotImplementedError("Method not implemented")

    def get_program_location(self) -> 'ProgramLocation':
        raise NotImplementedError("Method not implemented")

    def set_name(self, new_name: str, source_type: int):
        raise NotImplementedError("Method not implemented")

    def set_namespace(self, namespace: 'Namespace'):
        raise NotImplementedError("Method not implemented")

    def delete(self) -> bool:
        raise NotImplementedError("Method not implemented")

    def is_pinned(self) -> bool:
        raise NotImplementedError("Method not implemented")

    def set_pinned(self, pinned: bool):
        raise NotImplementedError("Method not implemented")

    def is_dynamic(self) -> bool:
        raise NotImplementedError("Method not implemented")

    def is_external(self) -> bool:
        raise NotImplementedError("Method not implemented")

    def is_primary(self) -> bool:
        raise NotImplementedError("Method not implemented")

    def set_primary(self) -> bool:
        raise NotImplementedError("Method not implemented")

    def is_external_entry_point(self) -> bool:
        raise NotImplementedError("Method not implemented")

    def get_id(self) -> int:
        raise NotImplementedError("Method not implemented")

    def get_object(self) -> object | None:
        raise NotImplementedError("Method not implemented")

    def is_global(self) -> bool:
        raise NotImplementedError("Method not implemented")

    def set_source(self, source_type: int):
        raise NotImplementedError("Method not implemented")

    def get_source(self) -> int:
        raise NotImplementedError("Method not implemented")

    def is_deleted(self) -> bool:
        raise NotImplementedError("Method not implemented")
