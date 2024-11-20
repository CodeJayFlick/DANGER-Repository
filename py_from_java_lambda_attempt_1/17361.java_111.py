Here's your Java code translated into Python:

```Python
class TracingPlan:
    def __init__(self, is_tracing_on):
        self.is_tracing_on = is_tracing_on

    @property
    def paths(self):
        return []

    @property
    def is_tracing_on(self):
        return self._is_tracing_on


# Usage example:

tracing_plan = TracingPlan(True)
print(tracing_plan.is_tracing_on)  # prints: True
```

Please note that Python does not have direct equivalent of Java's `OperatorType` and `PartialPath`. These are custom classes in your original code.