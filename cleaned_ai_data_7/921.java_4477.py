class DebugHostBase:
    def __init__(self):
        pass

    def get_context(self) -> 'DebugHostContext':
        raise NotImplementedError("Method not implemented")

    def enumerate_children(self, symbol_module: str, name: str) -> iter:
        raise NotImplementedError("Method not implemented")

    def get_symbol_kind(self) -> str:
        raise NotImplementedError("Method not implemented")

    def get_name(self) -> str:
        raise NotImplementedError("Method not implemented")

    def get_type(self) -> 'DebugHostType1':
        raise NotImplementedError("Method not implemented")

    def get_containing_module(self) -> 'DebugHostModule1':
        raise NotImplementedError("Method not implemented")

    def get_offset(self) -> int:
        raise NotImplementedError("Method not implemented")

    def get_jna_data(self) -> object:
        raise NotImplementedError("Method not implemented")
