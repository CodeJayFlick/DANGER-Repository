import logging

class SlidingTimeWindowConstructionTester:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def validate(self, parameters: dict) -> None:
        if not isinstance(parameters, dict):
            raise ValueError("Invalid input")
        if "input_series_number" in parameters and parameters["input_series_number"] != 1:
            raise ValueError("Input series number must be 1")
        if "input_series_data_type" in parameters and parameters["input_series_data_type"] != "INT32":
            raise ValueError("Input series data type must be INT32")

    def before_start(self, parameters: dict) -> None:
        self.logger.debug("SlidingTimeWindowConstructionTester#beforeStart")
        time_interval = int(parameters.get("time_interval", 0))
        configurations = {"output_data_type": "INT32",
                           "access_strategy": SlidingTimeWindowAccessStrategy(time_interval)}

    def transform(self, row_window: dict, collector: list) -> None:
        accumulator = 0
        for row in row_window["row_iterator"]:
            accumulator += int(row[0])
        if row_window["window_size"] != 0:
            collector.append((int(row_window["time"]), accumulator))

    def before_destroy(self) -> None:
        self.logger.debug("SlidingTimeWindowConstructionTester#beforeDestroy")

class SlidingTimeWindowAccessStrategy:
    def __init__(self, time_interval: int):
        self.time_interval = time_interval

    def get_access_strategy(self) -> dict:
        return {"time_interval": self.time_interval}

TIME_INTERVAL_KEY = "time_interval"
