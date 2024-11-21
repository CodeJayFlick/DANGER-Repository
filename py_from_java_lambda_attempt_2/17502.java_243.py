Here is the equivalent Python code:

```Python
class RowByRowAccessStrategy:
    def check(self):
        # nothing needs to be checked
        pass

    def get_access_strategy_type(self) -> str:
        return "ROW_BY_ROW"
```

Note that I've used type hints for `get_access_strategy_type` method, as Python 3.5 and later versions support this feature.