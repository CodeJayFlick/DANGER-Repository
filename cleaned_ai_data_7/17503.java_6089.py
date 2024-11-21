class SlidingSizeWindowAccessStrategy:
    def __init__(self, window_size: int, sliding_step: int = None):
        self.window_size = window_size
        if sliding_step is not None and sliding_step <= 0:
            raise ValueError("Parameter slidingStep should be positive.")
        if sliding_step is None:
            self.sliding_step = window_size
        else:
            self.sliding_step = sliding_step

    def check(self):
        if self.window_size <= 0:
            raise ValueError(f"Parameter windowSize({self.window_size}) should be positive.")

    @property
    def window_size(self) -> int:
        return self._window_size

    @window_size.setter
    def window_size(self, value: int):
        if value <= 0:
            raise ValueError("Window size must be greater than zero.")
        self._window_size = value

    @property
    def sliding_step(self) -> int:
        return self._sliding_step

    @sliding_step.setter
    def sliding_step(self, value: int):
        if value <= 0:
            raise ValueError("Sliding step must be greater than zero.")
        self._sliding_step = value

    def get_access_strategy_type(self) -> str:
        return "SLIDING_SIZE_WINDOW"
