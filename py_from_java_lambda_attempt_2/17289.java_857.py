Here is the translation of the Java code to Python:
```
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
```
Note that I used Python's built-in `property` decorator to create getter and setter methods for the `query_time` and `fill_type` attributes. This is equivalent to Java's private fields with public getters and setters.

Also, in Python, we don't need to specify types explicitly like we do in Java. The type of an attribute or variable is determined by its value at runtime.