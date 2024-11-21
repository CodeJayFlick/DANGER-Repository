Here is the translation of the Java code to Python:

```Python
class Metrics:
    def __init__(self):
        self.metrics = {}

    def add_metric(self, metric_name: str, value: float) -> None:
        if not self.metrics.get(metric_name):
            self.metrics[metric_name] = []
        self.metrics[metric_name].append((metric_name, value))

    def get_metrics(self, name: str) -> list:
        return self.metrics.get(name, [])

    def has_metric(self, name: str) -> bool:
        return name in self.metrics

    def latest_metric(self, name: str) -> tuple:
        if not self.has_metric(name):
            raise ValueError(f"Metric {name} does not exist")
        metrics = self.get_metrics(name)
        return metrics[-1]

    def percentile(self, metric_name: str, percentile: int) -> float:
        if not self.has_metric(metric_name):
            raise ValueError(f"Metric {metric_name} does not exist")

        metrics = sorted([m[1] for m in self.metrics[metric_name]])
        index = len(metrics) * (percentile / 100)
        return metrics[int(index)]

    def mean(self, metric_name: str) -> float:
        if not self.has_metric(metric_name):
            raise ValueError(f"Metric {metric_name} does not exist")

        return sum([m[1] for m in self.metrics[metric_name]]) / len(self.get_metrics(metric_name))
```

Please note that Python is an interpreted language and it doesn't support the concept of a static class like Java.