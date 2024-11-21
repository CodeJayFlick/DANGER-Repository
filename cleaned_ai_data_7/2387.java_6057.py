class DBTraceDefinedUnitsMemoryView:
    def __init__(self, manager):
        pass  # equivalent to super().__init__(manager)

    def get_view(self, space):
        return space.defined_units

    def clear(self, span: range, address_range: tuple, clear_context: bool, monitor=None) -> None:
        if monitor is not None and monitor.is_cancelled():
            raise CancelledException
        delegate_delete_v(address_range[0], lambda m: m.clear(span, address_range, clear_context, monitor))
