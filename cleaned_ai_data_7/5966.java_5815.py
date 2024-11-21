class GhidraTableFilterPanel(ROW_OBJECT):
    def __init__(self, table: JTable, row_object_table_model: RowObjectTableModel) -> None:
        super().__init__(table, row_object_table_model)

    def create_text_filter_model(self, model: RowObjectTableModel) -> 'RowObjectFilterModel[ROW_OBJECT]':
        new_model = super().create_text_filter_model(model)
        
        if isinstance(new_model, ThreadedTableModel):
            return new_model
        
        if not isinstance(model, ProgramTableModel):
            return new_model  # nope, the given model is not a ProgramTableModel; no new 
        else:
            return self._program_table_model_wrapper(new_model)

    def _program_table_model_wrapper(self, wrapped_filter_model: RowObjectFilterModel[ROW_OBJECT], wrapped_table_model: RowObjectFilterModel[ROW_OBJECT]) -> 'RowObjectFilterModel[ROW_OBJECT]':
        class ProgramTableModelWrapper(ROW_OBJECT):
            def __init__(self) -> None:
                self.wrapped_filter_model = wrapped_filter_model
                self.wrapped_table_model = wrapped_table_model

            @property
            def name(self) -> str:
                return self.wrapped_table_model.name()

            # ... (rest of the methods)

        return ProgramTableModelWrapper()
