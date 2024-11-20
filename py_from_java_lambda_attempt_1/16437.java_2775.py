Here is the equivalent Python code:

```
class GetEntriesWrongParametersException(Exception):
    def __init__(self, low, high):
        super().__init__(f"invalid get_entries: parameter {low} >= {high}")
```