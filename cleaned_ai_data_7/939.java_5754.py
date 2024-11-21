class DebugHostSymbol1:
    def compare_against(self, comparison_symbol: 'DebugHostSymbol1', comparison_flags: int) -> int:
        pass  # implement this method in your subclass

    @property
    def as_base_class(self):
        raise NotImplementedError("asBaseClass not implemented")

    @property
    def as_constant(self):
        raise NotImplementedError("asConstant not implemented")

    @property
    def as_data(self):
        raise NotImplementedError("asData not implemented")

    @property
    def as_field(self):
        raise NotImplementedError("asField not implemented")

    @property
    def as_module(self) -> 'DebugHostModule1':
        raise NotImplementedError("asModule not implemented")

    @property
    def as_public(self):
        raise NotImplementedError("asPublic not implemented")
