Here is a translation of the Java UDTF example into pure Python:

```Python
import datetime as dt

class UDTFExample:
    def before_start(self):
        pass  # No equivalent in Python

    def transform(self, row: dict) -> int:
        return -row['s1']

# Example usage:
data = [
    {'timestamp': dt.datetime(2022, 6, 15), 's1': -1, 's2': 1},
    {'timestamp': dt.datetime(2022, 6, 16), 's1': -2, 's2': 2},
    {'timestamp': dt.datetime(2022, 6, 17), 's1': -3, 's2': 3}
]

# Process the data
result = []
for row in data:
    result.append({'timestamp': row['timestamp'], 's1': UDTFExample().transform(row), 's2': row['s2']})

print(result)
```

Please note that this Python code does not exactly replicate the Java example. The `before_start` method is missing because there's no equivalent in Python, and I've used a simple dictionary to represent each data point instead of using an actual database or query API.

Also, please be aware that you may need additional libraries or modules depending on your specific use case.