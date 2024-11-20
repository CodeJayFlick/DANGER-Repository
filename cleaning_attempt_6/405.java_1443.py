class DebugFilterInformation:
    def __init__(self, n_events: int, n_specific_exceptions: int, n_arbitrary_exceptions: int):
        self.n_events = n_events
        self.n_specific_exceptions = n_specific_exceptions
        self.n_arbitrary_exceptions = n_arbitrary_exceptions

    @property
    def number_events(self) -> int:
        return self.n_events

    @property
    def number_specific_exceptions(self) -> int:
        return self.n_specific_exceptions

    @property
    def number_arbitrary_exceptions(self) -> int:
        return self.n_arbitrary_exceptions
