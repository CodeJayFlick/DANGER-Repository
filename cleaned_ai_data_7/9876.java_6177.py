class VariableColumnTableModel:
    @staticmethod
    def from_model(m):
        unwrapped = RowObjectTableModel.unwrap(m)
        if isinstance(unwrapped, VariableColumnTableModel):
            return unwrapped
        else:
            return None

    def get_column_display_name(self, column):
        pass  # implement this method in your subclass

    def get_column_description(self, column):
        pass  # implement this method in your subclass

    def get_unique_identifier(self, column):
        pass  # implement this method in your subclass

    def get_default_column_count(self):
        return -1  # default value; override in your subclass if needed

    def is_default_column(self, model_index):
        return False  # default value; override in your subclass if needed

    def is_visible_by_default(self, model_index):
        return False  # default value; override in your subclass if needed
