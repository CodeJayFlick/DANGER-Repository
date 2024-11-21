class ColumnTableFilterTest:
    def __init__(self):
        self.DATE_FORMAT = SimpleDateFormat("MM/dd/yyyy")
        self.table_model = None
        self.g_table = None
        self.filter_model = None
        self.all_constraints = load_constraints()

    @staticmethod
    def create_test_table():
        table_model = TableModelWrapper(TableModel())
        g_table = GTable(table_model)
        filter_model = ColumnFilterDialogModel(table_model, g_table.get_column_model(), None)

        return table_model, g_table, filter_model

    def setup(self):
        self.table_model, self.g_table, self.filter_model = create_test_table()
        add_first_filter("Name", "Starts With", "C")
        apply_filter()

    @staticmethod
    def load_constraints():
        all_constraints = []
        for _ in range(10):  # Replace with actual number of constraints.
            constraint = ColumnConstraint()  # Replace with actual column constraint class.
            all_constraints.append(constraint)
        return all_constraints

    def add_first_filter(self, column_name, constraint_name, constraint_value):
        filter_row = create_filter_row(LogicOperation.AND, True)
        column_data = get_column_filter_data(column_name)
        filter_row.set_column_data(column_data)

        condition = filter_row.get_filter_conditions()[0]
        condition.set_selected_constraint(constraint_name)
        condition.set_value(constraint_value, None)

    def apply_filter(self):
        table_column_filter = self.filter_model.get_table_column_filter()
        self.table_model.set_table_filter(table_column_filter)

    @staticmethod
    def get_column_filter_data(column_name):
        all_data = self.filter_model.get_all_column_filter_data()
        for column_filter_data in all_data:
            if column_filter_data.name == column_name:
                return column_filter_data

    # Other methods...

if __name__ == "__main__":
    test = ColumnTableFilterTest()
    test.setup()

