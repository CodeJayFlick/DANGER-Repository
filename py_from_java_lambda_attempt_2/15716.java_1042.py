Here is the translation of the Java code into Python:

```Python
import logging

class MultiFactorTracker:
    def __init__(self):
        self.base_value = None
        self.steps = []
        self.factor = 1
        self.step_index = 0

    @staticmethod
    def builder():
        return Builder()

    def get_new_value(self, num_update):
        while self.step_index <= len(self.steps) - 1:
            if num_update > self.steps[self.step_index]:
                self.step_index += 1
                self.base_value *= self.factor
                logging.debug(f"Update[{num_update}]: Change tracker value to {self.base_value:.5e}")
            else:
                return self.base_value

        return self.base_value


class Builder:
    def __init__(self):
        self.base_value = None
        self.steps = []
        self.factor = 1

    def set_base_value(self, base_value):
        self.base_value = base_value
        return self

    def set_steps(self, steps):
        if len(steps) <= 1:
            raise ValueError("Steps should be an array of integers indicating when the value should be changed")
        for i in range(len(steps)):
            if i > 0 and steps[i] <= steps[i - 1]:
                raise ValueError("Steps must be an increasing list")
            if steps[i] < 1:
                raise ValueError("Step must be larger or equal to 1")

        self.steps = steps
        return self

    def opt_factor(self, factor):
        if factor > 1.0:
            raise ValueError("factor should be no more than 1")
        self.factor = factor
        return self

    def build(self):
        if not self.steps:
            raise ValueError("Steps must be set to change value")

        tracker = MultiFactorTracker()
        tracker.base_value = self.base_value
        tracker.steps = self.steps
        tracker.factor = self.factor
        tracker.step_index = 0

        return tracker


logging.basicConfig(level=logging.DEBUG)
```

Note that Python does not have a direct equivalent of Java's `Logger` and `LoggerFactory`. Instead, we use the built-in `logging` module to configure logging.