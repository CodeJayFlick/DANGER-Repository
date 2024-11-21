Here is the equivalent Python code:

```Python
class QueryIndexPlan:
    def __init__(self):
        self.operator_type = "QUERY_INDEX"
        self.index_type = None
        self.props = {}

    @property
    def index_type(self):
        return self._index_type

    @index_type.setter
    def index_type(self, value):
        self._index_type = value

    @property
    def props(self):
        return self._props

    @props.setter
    def props(self, value):
        self._props = value

    def __eq__(self, other):
        if self is other:
            return True
        elif not isinstance(other, QueryIndexPlan):
            return False
        else:
            return (self.props == other.props and 
                    self.index_type == other.index_type)

    def __hash__(self):
        return hash((self.props, self.index_type))

    def __str__(self):
        return f"Query paths: {self.props}, index type: {self.index_type}, props: {self.props}"
```

Note that Python does not have an exact equivalent to Java's `@Override` annotation. The `__eq__`, `__hash__`, and `__str__` methods are implemented as special methods in Python, which is why they do not need the `@Override` annotation.