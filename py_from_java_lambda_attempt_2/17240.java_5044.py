Here is the translation of the given Java code into Python:

```Python
class CountOperator:
    def __init__(self, token_int_type: int, path: str):
        self.path = path
        super().__init__(token_int_type)

    def get_path(self) -> str:
        return self.path

    def get_level(self) -> int:
        return self.level

    @property
    def level(self) -> int:
        raise AttributeError("level is not set")

    def generate_physical_plan(self, generator: 'PhysicalGenerator') -> 'PhysicalPlan':
        if token_int_type == 1:
            return CountPlan(ShowContentType.COUNT_DEVICES, path)
        elif token_int_type == 2:
            return CountPlan(ShowContentType.COUNT_STORAGE_GROUP, path)
        elif token_int_type == 3:
            return CountPlan(ShowContentType.COUNT_NODE_TIMESERIES, path, level)
        elif token_int_type == 4:
            return CountPlan(ShowContentType.COUNT_NODES, path, level)
        elif token_int_type == 5:
            return CountPlan(ShowContentType.COUNT_TIMESERIES, path)
        else:
            raise LogicalOperatorException(f"Not supported operator type {token_int_type} in show operation.")
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation. Also, the `LogicalOperatorException` and other exceptions are not defined here as they were part of the original Java code.