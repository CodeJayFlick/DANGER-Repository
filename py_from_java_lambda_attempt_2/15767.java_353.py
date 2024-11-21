Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from statistics import median as percentile50

class Metrics:
    def __init__(self):
        self.metrics = {}

    def add_metric(self, name: str, value) -> None:
        if not isinstance(name, str):
            raise ValueError("Metric name must be a string")
        if not isinstance(value, (int, float)):
            raise TypeError("Value must be an integer or floating point number")

        if name in self.metrics:
            self.metrics[name].append(value)
        else:
            self.metrics[name] = [value]

    def get_metric(self, name: str) -> list:
        return self.metrics.get(name, [])

    def get_metric_names(self) -> set:
        return set(self.metrics.keys())

    def percentile(self, metric_name: str, percentile: int) -> float:
        values = self.get_metric(metric_name)
        if not values:
            raise ValueError(f"No data found for {metric_name}")
        sorted_values = sorted(values)
        index = (len(sorted_values) - 1) * percentile // 100
        return sorted_values[index]

    def mean(self, metric_name: str) -> float:
        values = self.get_metric(metric_name)
        if not values:
            raise ValueError(f"No data found for {metric_name}")
        return sum(values) / len(values)

class TestMetrics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.metrics = Metrics()

    def test_metrics(self):
        self.metrics.add_metric("m1", 1)
        self.metrics.add_metric("m1", 3, "count")
        self.metrics.add_metric("m1", 2)

        p50 = self.metrics.percentile("m1", 50)
        self.assertEqual(p50, 2.0)

        self.metrics.add_metric("m2", 1.0)
        self.metrics.add_metric("m2", 3.0, "count")
        self.metrics.add_metric("m2", 2.0)

        p50 = self.metrics.percentile("m2", 50)
        self.assertEqual(p50, 2.0)

        self.metrics.add_metric("m3", 1.0)
        self.metrics.add_metric("m3", 3.0, "count")
        self.metrics.add_metric("m3", 2.0)

        p50 = self.metrics.percentile("m3", 50)
        self.assertEqual(p50, 2.0)

        m1_values = self.metrics.get_metric("m1")
        self.assertEqual(len(m1_values), 3)

        m4_values = self.metrics.get_metric("m4")
        self.assertEqual(len(m4_values), 0)

        metric_names = set(self.metrics.get_metric_names())
        self.assertEqual(len(metric_names), 3)
        self.assertTrue("m1" in metric_names)
        self.assertTrue("m2" in metric_names)
        self.assertTrue("m3" in metric_names)
        self.assertFalse("m4" in metric_names)

    def test_metrics_mean(self):
        self.metrics.add_metric("m1", 2.4)
        self.metrics.add_metric("m1", 3.4, "count")
        self.metrics.add_metric("m1", -1.3)

        mean = self.metrics.mean("m1")
        self.assertEqual(mean, 1.5)

    def test_mean_exception(self):
        with self.assertRaises(IllegalArgumentException):
            self.metrics.mean("not_found")

    def test_percentile_exception(self):
        with self.assertRaises(ValueError):
            self.metrics.percentile("not_found", 50)


if __name__ == "__main__":
    unittest.main()
```

This Python code defines a `Metrics` class that provides methods for adding metrics, getting metric values and names, calculating the mean of a metric, and calculating the percentile (50th percentile) of a metric. The test cases are written using the `unittest` framework in Python.