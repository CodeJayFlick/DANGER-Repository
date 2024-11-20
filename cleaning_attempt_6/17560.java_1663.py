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
