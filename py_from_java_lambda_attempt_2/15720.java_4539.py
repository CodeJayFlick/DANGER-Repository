Here is the translation of the given Java code into Python:

```Python
class TrainingDivergedException(Exception):
    pass


class WarmUpTracker:
    def __init__(self, main_tracker, warm_up_steps, warm_up_begin_value, warm_up_final_value, warm_up_mode):
        self.main_tracker = main_tracker
        self.warm_up_steps = warm_up_steps
        self.warm_up_begin_value = warm_up_begin_value
        self.warm_up_final_value = warm_up_final_value
        self.warm_up_mode = warm_up_mode

    def get_warm_up_value(self, num_update):
        value = self.warm_up_begin_value
        if self.warm_up_mode == "LINEAR":
            value += (self.warm_up_final_value - self.warm_up_begin_value) * num_update / self.warm_up_steps
        return value

    def get_new_value(self, num_update):
        if num_update < self.warm_up_steps:
            return self.get_warm_up_value(num_update)
        else:
            return self.main_tracker.get_new_value(num_update - self.warm_up_steps)

    @staticmethod
    def check_value(value):
        if float('nan') in [value]:
            raise TrainingDivergedException("Value is Nan.")


class Builder:
    def __init__(self):
        pass

    def set_main_tracker(self, main_tracker):
        self.main_tracker = main_tracker
        return self

    def opt_warm_up_steps(self, warm_up_steps):
        self.warm_up_steps = warm_up_steps
        return self

    def opt_warm_up_begin_value(self, warm_up_begin_value):
        self.warm_up_begin_value = warm_up_begin_value
        return self

    def opt_warm_up_mode(self, warm_up_mode):
        self.warm_up_mode = warm_up_mode
        return self

    def build(self):
        return WarmUpTracker(
            main_tracker=self.main_tracker,
            warm_up_steps=self.warm_up_steps,
            warm_up_begin_value=self.warm_up_begin_value,
            warm_up_final_value=self.main_tracker.get_new_value(0),
            warm_up_mode=self.warm_up_mode
        )


class Mode:
    LINEAR = "LINEAR"
    CONSTANT = "CONSTANT"


def main():
    builder = Builder()
    # Example usage: create a WarmUpTracker with linear mode and 100 steps.
    tracker = builder.set_main_tracker(WarmUpTracker(0)).opt_warm_up_steps(100).opt_warm_up_mode(Mode.LINEAR).build()

if __name__ == "__main__":
    main()
```

This Python code defines the same classes as in Java: `TrainingDivergedException`, `WarmUpTracker`, and `Builder`. The methods are translated from their equivalent counterparts in Java.