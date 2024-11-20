class ThreadedTableColumnComparator:
    def __init__(self, model: 'ThreadedTableModel', sort_column: int):
        self.model = model
        super().__init__(model, sort_column)

    @property
    def threaded_model(self) -> 'ThreadedTableModel':
        return self.model

    def get_column_value(self, t: object) -> object:
        return self.threaded_model.get_cached_column_value_for_row(t, self.sort_column)
