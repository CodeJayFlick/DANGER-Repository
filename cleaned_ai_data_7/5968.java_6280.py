class IncomingReferencesTableModel:
    def __init__(self, title: str, serviceProvider, program: object, references: list, monitor):
        self.refs = references
        super().__init__(title, serviceProvider, program, monitor)

    def get_address(self, row: int) -> object:
        return self.get_row_object(row).get_address()

    def do_load(self, accumulator: dict, monitor) -> None:
        for r in self.refs:
            accumulator.add(r)
