class WhereComponent:
    def __init__(self):
        self.filter_operator = None

    def __init__(self, filter_operator: 'FilterOperator'):
        self.filter_operator = filter_operator

    @property
    def filter_operator(self):
        return self._filter_operator

    @filter_operator.setter
    def filter_operator(self, value: 'FilterOperator'):
        self._filter_operator = value


class FilterOperator:
    pass  # This is a placeholder class, you'll need to define the actual implementation in Python
