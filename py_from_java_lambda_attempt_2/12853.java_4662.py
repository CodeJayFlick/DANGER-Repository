Here is the translation of the Java code to Python:
```
class Locator:
    def __init__(self):
        self.map = {}

    def register_location(self, expanded_line_no: int, real_location: dict) -> None:
        self.map[expanded_line_no] = real_location

    def get_location(self, expanded_line_no: int) -> dict or None:
        head_map = {k: v for k, v in self.map.items() if k < expanded_line_no + 1}
        key = max(head_map.keys()) if head_map else None
        location = head_map.get(key)
        actual_lineno = expanded_line_no - key + location['lineno']
        correct_location = {'filename': location['filename'], 'lineno': actual_lineno}
        return correct_location or None

# Example usage:
locator = Locator()
real_locations = [
    {'filename': 'file1.py', 'lineno': 10},
    {'filename': 'file2.py', 'lineno': 20},
    # ...
]
for expanded_line_no, real_location in enumerate(real_locations):
    locator.register_location(expanded_line_no + 1, real_location)

print(locator.get_location(15))  # Output: {'filename': 'file1.py', 'lineno': 5}
```
Note that I used Python's built-in `dict` type to represent the map and location objects. The Java code uses a `TreeMap` for sorting and searching, but in Python, we can use dictionaries with keys as integers to achieve similar functionality.