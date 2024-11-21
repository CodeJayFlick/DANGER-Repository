Here is the translation of the given Java code into Python:

```Python
import logging

class Counter:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)

    def before_start(self, parameters, configurations):
        self.logger.debug("Counter#beforeStart")
        configurations.output_data_type = "INT32"
        access_strategy_key = parameters.getOrDefault('accessStrategyKey', 'ROW_BY_ROW')
        if access_strategy_key == 'SLIDING_SIZE':
            configurations.access_strategy = SlidingSizeWindowAccessStrategy(parameters['windowSize'])
        elif access_strategy_key == 'SLIDING_TIME':
            sliding_step = parameters.get('slidingStep')
            display_window_begin = parameters.get('displayWindowBegin')
            display_window_end = parameters.get('displayWindowEnd')
            if all([sliding_step, display_window_begin, display_window_end]):
                configurations.access_strategy = SlidingTimeWindowAccessStrategy(parameters['timeInterval'], sliding_step, display_window_begin, display_window_end)
            else:
                configurations.access_strategy = SlidingTimeWindowAccessStrategy(parameters['timeInterval'])
        elif access_strategy_key == 'ROW_BY_ROW':
            configurations.access_strategy = RowByRowAccessStrategy()
        else:
            raise ValueError("Invalid Access Strategy")

    def transform(self, row, collector):
        collector.put_int(row.time(), 1)

    def transform_window(self, row_window, collector):
        if row_window.window_size() != 0:
            collector.put_int(row_window.row(0).time(), row_window.window_size())

    def before_destroy(self):
        self.logger.debug("Counter#beforeDestroy")

class SlidingSizeWindowAccessStrategy:
    def __init__(self, window_size):
        self.window_size = window_size

class RowByRowAccessStrategy:
    pass

class SlidingTimeWindowAccessStrategy:
    def __init__(self, time_interval, sliding_step=None, display_window_begin=None, display_window_end=None):
        self.time_interval = time_interval
        self.sliding_step = sliding_step
        self.display_window_begin = display_window_begin
        self.display_window_end = display_window_end

if __name__ == "__main__":
    counter = Counter()
```

Please note that this translation is not a direct conversion from Java to Python. The original code seems to be part of an IoTDB UDF (User-Defined Function) and some parts may require additional context or modifications for correct functionality in the target language, which is Python in this case.