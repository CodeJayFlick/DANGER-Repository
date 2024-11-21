class TraceFunctionSymbolView:
    def add(self, lifespan: range, entry_point: int, body_view: set[int], name: str, thunked: 'TraceFunctionSymbol', parent: 'TraceNamespaceSymbol', source_type: str) -> 'TraceFunctionSymbol':
        # Implement the logic for adding a trace function symbol
        pass

    def create(self, snap: int, entry_point: int, body_view: set[int], name: str, thunked: 'TraceFunctionSymbol', parent: 'TraceNamespaceSymbol', source_type: str) -> 'TraceFunctionSymbol':
        return self.add(range(snap), entry_point, body_view, name, thunked, parent, source_type)

    def get_calling_conventions(self) -> list['PrototypeModel']:
        # Implement the logic for getting calling conventions
        pass

    def get_calling_convention_names(self) -> list[str]:
        # Implement the logic for getting calling convention names
        pass

    def get_default_calling_convention(self) -> 'PrototypeModel':
        # Implement the logic for getting default calling convention
        pass

    def get_calling_convention(self, name: str) -> 'PrototypeModel':
        # Implement the logic for getting a specific calling convention by name
        pass


class PrototypeModel:
    pass


class TraceFunctionSymbol:
    pass


class TraceNamespaceSymbol:
    pass
