class QueryExpression:
    def __init__(self):
        self.selected_series = []
        self.data_types = None
        self.expression = None
        self.has_query_filter = False

    @staticmethod
    def create():
        return QueryExpression()

    @staticmethod
    def create(selected_series, expression):
        query_expression = QueryExpression()
        query_expression.selected_series = selected_series
        query_expression.expression = expression
        if expression is not None:
            query_expression.has_query_filter = True
        return query_expression

    def add_selected_path(self, path):
        self.selected_series.append(path)
        return self

    def set_select_series(self, selected_series):
        self.selected_series = selected_series
        return self

    def get_expression(self):
        return self.expression

    def set_expression(self, expression):
        if expression is not None:
            self.expression = expression
            self.has_query_filter = True
        return self

    def get_selected_series(self):
        return self.selected_series

    def __str__(self):
        selected_series_str = str(self.selected_series)
        data_types_str = str(self.data_types) if self.data_types else 'None'
        expression_str = str(self.expression) if self.expression is not None else 'None'

        return f"""
Selected Series: {selected_series_str}
TSDataType: {data_types_str}
Expression: {expression_str}"""

    def has_query_filter(self):
        return self.has_query_filter

    def get_data_types(self):
        return self.data_types

    def set_data_types(self, data_types):
        self.data_types = data_types
        return self
