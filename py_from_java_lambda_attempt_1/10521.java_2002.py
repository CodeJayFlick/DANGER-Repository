Here is the translation of the Java code into Python:

```Python
class VariableRowHeightGridLayout:
    def __init__(self, column_count):
        self.vgap = 0
        self.hgap = 0
        self.column_count = column_count

    def get_row_height(self, parent, row):
        row_height = 0
        component_count = len(parent.get_children())
        for i in range(component_count // self.column_count + (component_count % self.column_count > 0)):
            if i >= row * self.column_count:
                return row_height
            ordinal = row * self.column_count + i
            if ordinal >= component_count:
                break
            component = parent.get_children()[ordinal]
            d = component.get_preferred_size()
            row_height = max(row_height, d.height)
        return row_height

    def get_preferred_column_width(self, parent):
        width = 0
        for i in range(len(parent.get_children())):
            component = parent.get_children()[i]
            d = component.get_preferred_size()
            width = max(width, d.width)
        return width

    def layout_container(self, parent):
        component_count = len(parent.get_children())
        row_count = (component_count + self.column_count - 1) // self.column_count
        size = parent.get_size()
        insets = parent.get_insets()
        width = size.width - (insets.left + insets.right)
        total_columns = min(self.column_count, component_count)
        available_column_width = (width - (self.column_count - 1) * self.hgap) // total_columns
        column_width = self.get_preferred_column_width(parent)
        y = insets.top
        for i in range(row_count):
            x = insets.left
            row_height = self.get_row_height(parent, i)
            for j in range(self.column_count):
                ordinal = i * self.column_count + j
                if ordinal >= component_count:
                    break
                component = parent.get_children()[ordinal]
                component.set_bounds(x, y, column_width, row_height)
                x += column_width + self.hgap
            y += row_height + self.vgap

    def get_preferred_size(self, parent):
        component_count = len(parent.get_children())
        row_count = (component_count + self.column_count - 1) // self.column_count
        total_component_height = sum([self.get_row_height(parent, i) for i in range(row_count)])
        total_columns = min(self.column_count, component_count)
        total_component_width = self.get_preferred_column_width(parent) * total_columns
        size = Dimension(total_component_width + (self.column_count - 1) * self.hgap + insets.left + insets.right,
                         total_component_height + (row_count - 1) * self.vgap + insets.top + insets.bottom)
        return size

    def get_minimum_size(self, parent):
        return self.get_preferred_size(parent)

class Dimension:
    def __init__(self, width, height):
        self.width = width
        self.height = height

    @property
    def width(self):
        return self._width

    @width.setter
    def width(self, value):
        self._width = value

    @property
    def height(self):
        return self._height

    @height.setter
    def height(self, value):
        self._height = value
```

Please note that Python does not have direct equivalents for Java's `Container`, `Component`, and `LayoutManager` classes. In this translation, I used a simple list to represent the container (parent) and its children (components). The layout manager is implemented as an instance of the `VariableRowHeightGridLayout` class.