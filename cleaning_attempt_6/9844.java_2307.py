class TableColumnDescriptor:
    def __init__(self):
        self.columns = []

    def get_all_columns(self):
        all_columns = []
        for column_info in self.columns:
            all_columns.append(column_info.column)
        return all_columns

    def get_default_visible_columns(self):
        default_visible_columns = []
        for column_info in self.columns:
            if column_info.is_visible:
                default_visible_columns.append(column_info.column)
        return default_visible_columns

    def get_default_table_sort_state(self, model):
        sorted_columns = sorted(self.columns, key=lambda x: x.sort_index)
        editor = TableSortStateEditor()
        
        for column_info in sorted_columns:
            if column_info.sort_index == -1:
                continue
            column_index = model.get_column_index(column_info.column)
            editor.add_sorted_column(column_index)
            if not column_info.ascending:
                editor.flip_column_sort_direction(column_index)

        return editor.create_table_sort_state()

    def remove(self, column):
        for i in range(len(self.columns)):
            column_info = self.columns[i]
            if column_info.column == column:
                del self.columns[i]
                return i
        return -1

    def set_hidden(self, column):
        index = self.remove(column)
        self.columns.insert(index, {'column': column})

    def add_hidden_column(self, column):
        self.columns.append({'column': column})

    def add_visible_column(self, column):
        self.add_visible_column(column, -1, True)

    def add_visible_column(self, column, sort_ordinal, ascending):
        self.columns.append({
            'column': column,
            'is_visible': True,
            'sort_index': sort_ordinal,
            'ascending': ascending
        })

class TableColumnInfo:
    def __init__(self, column, is_visible=False, sort_index=-1, ascending=True):
        self.column = column
        self.is_visible = is_visible
        self.sort_index = sort_index
        self.ascending = ascending

    def __lt__(self, other):
        return self.sort_index < other.sort_index


class TableSortStateEditor:
    pass  # This class needs to be implemented based on the requirements of your application.
