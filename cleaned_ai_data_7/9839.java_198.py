class ColumnRenderedValueBackupComparator:
    def __init__(self, model: 'DynamicColumnTableModel', sort_column):
        self.model = model
        self.sort_column = sort_column
        
        column = self.model.get_column(sort_column)
        if not isinstance(column.renderer, GColumnRenderer) or \
           column.renderer.column_constraint_filter_mode == ALLOW_CONSTRAINTS_FILTER_ONLY:
            self.supports_column_sorting = False

    def compare(self, c1: object, c2: object):
        if c1 is c2:
            return 0
        
        s1 = self.get_rendered_column_string_value(c1)
        s2 = self.get_rendered_column_string_value(c2)

        if not (s1 and s2): 
            return TableComparators.compare_with_null_values(s1, s2) 

        return s1.casefold() == s2.casefold()

    def get_rendered_column_string_value(self, column_value: object):
        if not self.supports_column_sorting:
            return None

        column = self.model.get_column(self.sort_column)
        renderer = column.renderer
        settings = self.model.get_column_settings(self.sort_column)

        if renderer is None:
            return str(column_value) if column_value else None
        
        return renderer.filter_string(column_value, settings)

    def get_column_value(self, t: object):
        return self.model.get_column_value_for_row(t, self.sort_column)
