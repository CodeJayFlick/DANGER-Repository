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
