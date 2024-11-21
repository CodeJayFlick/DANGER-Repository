Here is the translation of the Java code to Python:

```Python
class RangeTableCellRenderer:
    def __init__(self):
        self.double_full_range = (0, 1)
        self.span = 1
        self.full_range = None
        self.data_range = None

    @staticmethod
    def validate_view_range(full_range):
        if not full_range.has_lower_bound() or not full_range.has_upper_bound():
            raise ValueError("Cannot have unbounded full range")
        return (full_range.lower_endpoint(), full_range.upper_endpoint())

    def set_full_range(self, full_range):
        self.full_range = full_range
        self.double_full_range = RangeTableCellRenderer.validate_view_range(full_range)
        self.span = self.double_full_range[1] - self.double_full_range[0]

    def get_filter_string(self, t, settings):
        return ""

    def get_table_cell_renderer_component(self, data):
        self.data_range = data.get_value()
        super().get_table_cell_renderer_component(data)
        self.set_text("")
        return self

    def paint_component(self, parent_g):
        if not self.data_range:
            return
        width, height = parent_g.size()

        x1 = 0
        y1 = 0
        x2 = width
        y2 = height - 1

        g = parent_g.create()
        g.set_color(get_foreground())
        g.fill_rect(x1, y1, x2 - x1, y2 - y1)

    def interpolate(self, w, val):
        lower, upper = self.double_full_range
        if val <= lower:
            return 0
        elif val >= upper:
            return w
        else:
            dif = val - lower
            return int(dif / (upper - lower) * w)

    @property
    def full_range(self):
        return self._full_range

    @full_range.setter
    def full_range(self, value):
        self._full_range = value
```

Please note that Python does not have direct equivalent of Java's generics. So I removed the type parameter `<N extends Number & Comparable<N>>` from the class definition and method parameters.