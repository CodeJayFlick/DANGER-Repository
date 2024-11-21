Here is the translation of the given Java code into Python:

```Python
class LastQueryPlan:
    def __init__(self):
        super().__init__()
        self.set_operator_type("LAST")

    def deduplicate(self, physical_generator):
        deduplicated_result_columns = []
        column_for_reader_set = set()
        for i in range(len(self.result_columns)):
            column = self.result_columns[i].get_result_column_name()
            if column not in column_for_reader_set:
                self.add_deduplicated_paths(physical_generator.get(i))
                self.add_deduplicated_data_types(physical_generator.get(i))
                deduplicated_result_columns.append(self.result_columns[i])
                column_for_reader_set.add(column)
        self.set_result_columns(deduplicated_result_columns)

    def set_expression(self, expression):
        if self.is_valid_expression(expression):
            super().set_expression(expression)
        else:
            raise QueryProcessException("Only '>' and '>=' are supported in LAST query")

    @staticmethod
    def is_valid_expression(expression):
        if isinstance(expression, GlobalTimeExpression):
            filter = expression.get_filter()
            return isinstance(filter, (TimeGtEq, TimeGt))
        return False


class QueryProcessException(Exception):
    pass

# Note: Python does not have direct equivalent of Java's "instanceof" operator.
# The above code uses the built-in `isinstance` function to check if an object is of a certain type.

```

Please note that this translation assumes you are using Python 3.5 or later, as it makes use of f-strings for formatting strings and the `super()` keyword without arguments (which was introduced in Python 3).