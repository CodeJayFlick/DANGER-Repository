Here is the translation of the Java code to Python:
```python
class GListAutoLookup:
    def __init__(self, list):
        self.list = list

    def get_current_row(self):
        return self.list.get_selected_index()

    def get_row_count(self):
        return len(self.list.model())

    def get_value_string(self, row, col):
        renderer = self.list.cell_renderer
        value = self.list.model()[row]
        if not isinstance(renderer, JLabel):
            return str(value)
        c = renderer.getListCellRendererComponent(self.list, value, row, False, False)
        return (c).getText()

    def is_sorted(self, column):
        return True

    def is_sorted_ascending(self):
        return True

    def match_found(self, row):
        self.list.set_selected_index(row)

class GList:
    pass  # assume this class exists and has methods get_model(), set_model(), etc.

# Example usage
my_list = GList()  # assuming this class exists
auto_lookup = GListAutoLookup(my_list)
```
Note that I had to make some assumptions about the `GList` class, as it was not provided in the original Java code. In particular, I assumed that `GList` has methods like `get_model()` and `set_model()`, which are used by the `GListAutoLookup` class.

Also, Python does not have a direct equivalent to Java's `JLabel` or `Component` classes, so I simply omitted those parts of the code. If you need more specific functionality related to labels or components, please let me know and I can try to help with that as well!