Here is the equivalent Python code:

```Python
class TestDataModel:
    def __init__(self):
        self.data = []

    def load_data(self, file_name):
        try:
            with open(file_name, 'r') as f:
                data = [line.strip().split(',') for line in f.readlines()]
                return [{'date': row[0], 'time': row[1], 'directory': bool(int(row[2])), 'size': int(row[3]), 'name': row[4]} for row in data]
        except FileNotFoundError:
            print(f"File {file_name} not found.")
            return []

    def get_data(self):
        return self.data

    def set_data(self, new_data):
        self.data = new_data

    def get_column_names(self):
        return ['Date', 'Time', 'Directory', 'Size', 'Name']

    def is_sortable(self, column_index):
        return True
```

This Python code does not have direct equivalent of Java's `AbstractSortedTableModel` and its methods. The provided code only translates the main logic of your original Java class into a simple Python class.

Please note that this translation assumes you are using Python 3.x as it uses f-strings for formatting strings, which is available in Python 3.6+.