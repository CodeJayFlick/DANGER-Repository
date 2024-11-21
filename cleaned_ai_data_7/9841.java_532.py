class RowBasedColumnComparator:
    def __init__(self, model: 'RowObjectTableModel', sort_column: int, comparator: callable):
        self.model = model
        self.sort_column = sort_column
        self.column_comparator = comparator

    @staticmethod
    def compare(t1, t2) -> int:
        if t1 == t2:
            return 0
        
        value1 = RowBasedColumnComparator.get_column_value(t1)
        value2 = RowBasedColumnComparator.get_column_value(t2)

        if value1 is None or value2 is None:
            return TableComparators.compare_with_null_values(value1, value2)

        result = self.column_comparator(value1, value2)
        if result != 0:
            return result

        # At this point we have one of two cases: 
        # 1) the column comparator is a non-default comparator that has returned 0, which means
        #    the column values should sort the same, or
        # 2) the column comparator is a default/non-specific comparator, which means that the 
        #    column values should sort the same, or *that the default comparator could not 
        #    figure out how to sort them.
        #
        # In case 1, this backup comparator will be just a stub comparator; in case 2, this 
        # backup comparator is not a stub and will do something reasonable for the sort, 
        # depending upon how the model created this class.
        return self.backup_row_comparator(value1, value2)

    @staticmethod
    def get_column_value(t) -> object:
        return RowBasedColumnComparator.model.get_column_value_for_row(t, RowBasedColumnComparator.sort_column)
