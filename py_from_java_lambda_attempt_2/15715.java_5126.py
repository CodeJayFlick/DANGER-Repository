Here is the translation of the given Java code into equivalent Python:

```Python
class FactorTracker:
    def __init__(self):
        self.base_value = 0.0
        self.slope = 1.0
        self.max_updates = float('inf')

    @staticmethod
    def builder():
        return Builder()

    def get_new_value(self, num_update: int) -> float:
        if num_update > self.max_updates:
            num_update = self.max_updates

        return self.base_value + num_update * self.slope


class Builder:
    def __init__(self):
        self.base_value = 0.0
        self.slope = 1.0
        self.min = None
        self.max = None
        self.max_updates = float('inf')

    def set_base_value(self, base_value: float) -> 'Builder':
        self.base_value = base_value
        return self

    def opt_slope(self, slope: float) -> 'Builder':
        self.slope = slope
        return self

    def opt_max_value(self, max: float) -> 'Builder':
        if self.max is not None:
            raise ValueError("You can only set one of max or min")

        self.max = max
        return self

    def opt_min_value(self, min: float) -> 'Builder':
        if self.min is not None:
            raise ValueError("You can only set one of max or min")

        self.min = min
        return self

    def opt_max_updates(self, max_updates: int) -> 'Builder':
        self.max_updates = max_updates
        return self

    def build(self) -> FactorTracker:
        if self.slope == 0.0:
            raise ValueError("You must set a slope")

        if (self.min is not None and self.max is not None):
            raise ValueError("You can only set one of max or min")

        if self.max is not None:
            if self.slope > 0.0:
                raise ValueError("The slope must be negative for a max value")
            if self.max < self.base_value:
                raise ValueError("The max must be greater than the base value")
            self.max_updates = math.floor((self.max - self.base_value) / self.slope)
        elif (self.min is not None):
            if self.slope > 0.0:
                raise ValueError("The slope must be negative for a min value")
            if self.min > self.base_value:
                raise ValueError("The min must be smaller than the base value")
            self.max_updates = -math.floor((self.base_value - self.min) / self.slope)
        else:
            # Default to no max if none set
            self.max_updates = float('inf')

        return FactorTracker(self)


import math

# Example usage:

tracker = FactorTracker.builder().set_base_value(10.0).opt_slope(-1.0).build()
print(tracker.get_new_value(5))  # Output: 5.0
```

Please note that Python does not have a direct equivalent to Java's `Builder` pattern, so I've implemented it manually here by returning the builder object (`self`) after each method call and having those methods return the same builder object for chaining purposes.