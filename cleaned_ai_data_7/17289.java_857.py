class FillQueryPlan:
    def __init__(self):
        super().__init__()
        self.operator_type = "FILL"

    @property
    def query_time(self):
        return self._query_time

    @query_time.setter
    def query_time(self, value):
        self._query_time = value

    @property
    def fill_type(self):
        return self._fill_type

    @fill_type.setter
    def fill_type(self, value):
        self._fill_type = value


# Example usage:
fill_query_plan = FillQueryPlan()
print(fill_query_plan.operator_type)  # Output: FILL
fill_query_plan.query_time = 12345
print(fill_query_plan.query_time)  # Output: 12345

fill_types = {"int": "some_fill_method", "float": "another_fill_method"}
fill_query_plan.fill_type = fill_types
print(fill_query_plan.fill_type)  # Output: {'int': 'some_fill_method', 'float': 'another_fill_method'}
