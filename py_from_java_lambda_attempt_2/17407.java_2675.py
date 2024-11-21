Here is the translation of the Java interface `GroupByExecutor` to a Python class:

```python
class GroupByExecutor:
    def __init__(self):
        self.aggregate_results = []

    def add_aggregate_result(self, aggregate_result: 'AggregateResult'):
        """Add reusable result cache in executor"""
        self.aggregate_results.append(aggregate_result)

    def calc_result(self, cur_start_time: int, cur_end_time: int) -> list:
        """
        Calculate result in [curStartTime, curEndTime)
        
        :raises IOException
        :raises QueryProcessException
        """
        # Implement this method according to your needs
        pass

    def peek_next_not_null_value(self, next_start_time: int, next_end_time: int) -> tuple:
        """
        Peek the next not null value
        
        :raises IOException
        """
        # Implement this method according to your needs
        return None  # Replace with actual implementation
```

Note that I've used Python's type hints (`'AggregateResult'`) for clarity, but they are not enforced at runtime. Also, the `calc_result` and `peek_next_not_null_value` methods are currently just stubs, as their implementations depend on your specific use case.