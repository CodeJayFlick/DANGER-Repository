Here's your Java class translated into a Python class:

```Python
class QueryData:
    def __init__(self, query_string: str, case_sensitive: bool, include_dynamic_labels: bool):
        self.query_string = query_string
        self.case_sensitive = case_sensitive
        self.include_dynamic_labels = include_dynamic_labels

    @classmethod
    def from_query_and_case(cls, query_string: str, case_sensitive: bool) -> 'QueryData':
        return cls(query_string, case_sensitive, True)

    def get_query_string(self):
        return self.query_string

    def is_case_sensitive(self):
        return self.case_sensitive

    def include_dynamic_labels(self):
        return self.include_dynamic_labels
```

Please note that Python does not have an exact equivalent of Java's `super()` method. The `@classmethod` decorator in the above code allows you to create a classmethod, which can be used as a factory for creating instances of your class.