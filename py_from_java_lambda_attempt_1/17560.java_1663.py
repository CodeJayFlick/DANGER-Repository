Here is the translation of the given Java code into equivalent Python:

```Python
class IntermediateLayer:
    CACHE_BLOCK_SIZE = 2

    def __init__(self, expression: 'Expression', query_id: int, memory_budget_in_mb: float):
        self.expression = expression
        self.query_id = query_id
        self.memory_budget_in_mb = memory_budget_in_mb

    @abstractmethod
    def construct_point_reader(self) -> 'LayerPointReader':
        pass

    @abstractmethod
    def construct_row_reader(self) -> 'LayerRowReader':
        pass

    def construct_row_window_reader(self, strategy: 'AccessStrategy', memory_budget_in_mb: float) -> 'LayerRowWindowReader':
        if isinstance(strategy, SlidingTimeWindowAccessStrategy):
            return self.construct_row_sliding_time_window_reader(strategy, memory_budget_in_mb)
        elif isinstance(strategy, SlidingSizeWindowAccessStrategy):
            return self.construct_row_sliding_size_window_reader(strategy, memory_budget_in_mb)
        else:
            raise ValueError(f"Unexpected access strategy: {strategy.get_access_strategy_type()}")

    @abstractmethod
    def construct_row_sliding_size_window_reader(self, strategy: 'SlidingSizeWindowAccessStrategy', memory_budget_in_mb: float) -> 'LayerRowWindowReader':
        pass

    @abstractmethod
    def construct_row_sliding_time_window_reader(self, strategy: 'SlidingTimeWindowAccessStrategy', memory_budget_in_mb: float) -> 'LayerRowWindowReader':
        pass

    def __str__(self):
        return str(self.expression)
```

Note that I've used type hints for the method parameters and return types. This is not strictly necessary in Python, but it can help with code readability and catch potential errors at runtime.

Also note that I haven't implemented any of the abstract methods (`construct_point_reader`, `construct_row_reader`, etc.), as these would depend on specific details about how you want to implement those methods in your particular use case.