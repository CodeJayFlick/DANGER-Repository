class DBTraceNamespaceSymbolView:
    def __init__(self, manager):
        super().__init__(manager, "NAMESPACE", manager.namespace_store)

    def add(self, name: str, parent: dict, source: str) -> tuple:
        if source == "DEFAULT":
            raise ValueError("Invalid input")
        try:
            dbns_parent = self.manager.assert_is_mine(parent)
            self.manager.assert_unique_name(name, dbns_parent)
            namespace = self.store.create()
            namespace.set(name, dbns_parent, source)
            self.manager.trace.set_changed(
                TraceChangeRecord(TraceSymbolChangeType.ADDED, None, namespace))
            return namespace
        except (DuplicateNameException, InvalidInputException):
            raise

    def construct_view(self) -> list:
        return [namespace for namespace in self.store.as_map().values() if namespace]

class DBTraceNamespaceSymbol:
    def __init__(self, name: str, parent: dict, source: str):
        self.name = name
        self.parent = parent
        self.source = source

    def set(self, name: str, parent: dict, source: str):
        self.name = name
        self.parent = parent
        self.source = source

class TraceChangeRecord:
    def __init__(self, change_type: int, old_value: any, new_value: any):
        self.change_type = change_type
        self.old_value = old_value
        self.new_value = new_value

class DBTraceSymbolManager:
    @staticmethod
    def assert_valid_name(name: str) -> None:
        pass  # implement me!

    @staticmethod
    def assert_is_mine(obj: dict) -> dict:
        return obj

    @staticmethod
    def assert_unique_name(name: str, parent: dict) -> None:
        pass  # implement me!

    def set_changed(self, record: TraceChangeRecord):
        pass  # implement me!
