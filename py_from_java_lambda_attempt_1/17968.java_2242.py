Here is the translation of the Java code to Python:
```python
import logging

class Max:
    def __init__(self):
        self.time = None
        self.value = 0

    @staticmethod
    def get_logger():
        return logging.getLogger(__name__)

    def validate(self, parameters):
        pass  # No validation needed in this example

    def before_start(self, parameters, configurations):
        logger.debug("Max#beforeStart")
        configurations.output_data_type = "INT32"
        configurations.access_strategy = RowByRowAccessStrategy()

    def transform(self, row, collector):
        candidate_value = int(row[0])
        if self.time is None or self.value < candidate_value:
            self.time = row[1]
            self.value = candidate_value

    def terminate(self, collector):
        if self.time is not None:
            collector.put_int(self.time, self.value)

    def before_destroy(self):
        logger.debug("Max#beforeDestroy")

if __name__ == "__main__":
    max_udf = Max()
```
Note that I did not include the `UDTF`, `Row`, `PointCollector`, and other Java-specific classes in this translation. Instead, I focused on translating the logic of the code to Python.

Also, please note that this is a simplified translation, as some parts of the original code (e.g., error handling) have been omitted for brevity's sake.