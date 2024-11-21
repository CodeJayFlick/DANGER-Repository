Here is the translation of the Java code into Python:

```Python
class MaximizeSpecificColumnGridLayout:
    def __init__(self, column_count):
        self.vgap = 0
        self.hgap = 0
        self.column_count = column_count
        self.maximized_columns = [False] * column_count

    def maximize_column(self, column: int) -> None:
        self.maximized_columns[column] = True

    def preferred_layout_size(self, parent):
        component_count = len(parent.get_children())
        row_count = (component_count + (self.column_count - 1)) // self.column_count
        insets = parent.cget('borderwidth')
        d = [0, 0]
        total_component_height = 0
        for i in range(row_count):
            total_component_height += get_row_height(parent, i)
        desired_column_widths = get_desired_column_widths(parent)

        total_component_width = sum(desired_column_widths)
        d[0] = total_component_width + self.hgap * (self.column_count - 1) + insets['left'] + insets['right']
        d[1] = total_component_height + self.vgap * (row_count - 1) + insets['top'] + insets['bottom']
        return tuple(d)

    def get_row_height(self, parent: object, row: int):
        height = 0
        for i in range(self.column_count):
            ordinal = row * self.column_count + i
            if ordinal >= len(parent.get_children()):
                break
            component = parent.winfo_children()[ordinal]
            d = component.cget('height')
            height = max(height, int(d))
        return height

    def minimum_layout_size(self, parent: object):
        return self.preferred_layout_size(parent)

    def layout_container(self, parent: object):
        component_count = len(parent.get_children())
        row_count = (component_count + (self.column_count - 1)) // self.column_count
        d = parent.cget('width')
        insets = parent.cget('borderwidth')
        width = int(d) - (insets['left'] + insets['right'])
        desired_column_widths = get_desired_column_widths(parent)
        computed_column_widths = [0] * self.column_count
        for i in range(self.column_count):
            if self.maximized_columns[i]:
                computed_column_widths[i] = max(computed_column_widths[i], desired_column_widths[i])
        y = insets['top']
        for i in range(row_count):
            x = insets['left'] + (width - sum(desired_column_widths)) // 2
            row_height = get_row_height(parent, i)
            for j in range(self.column_count):
                ordinal = i * self.column_count + j
                if ordinal >= component_count:
                    break
                component = parent.winfo_children()[ordinal]
                computed_column_widths[j] += int(component.cget('width'))
                x += computed_column_widths[j] + self.hgap
            y += row_height + self.vgap

    def get_desired_maximized_width(self, desired_widths):
        width = 0
        for i in range(len(desired_widths)):
            if self.maximized_columns[i]:
                width += desired_widths[i]
        return width

    def get_computed_column_widths(self, parent: object) -> list:
        computed_column_widths = [0] * len(parent.winfo_children())
        remaining_maximized_count = sum(1 for i in range(len(computed_column_widths)) if self.maximized_columns[i])
        average_maximized_width = 0
        while True:
            found_one = False
            for i in range(len(computed_column_widths)):
                if computed_column_widths[i] == 0 and desired_column_widths[i] < average_maximized_width:
                    computed_column_widths[i] = int(desired_column_widths[i])
                    remaining_maximized_count -= 1
                    found_one = True
            if not found_one:
                break
        for i in range(len(computed_column_widths)):
            if self.maximized_columns[i]:
                computed_column_widths[i] += average_maximized_width // (remaining_maximized_count + 1)
        return computed_column_widths

    def get_desired_column_widths(self, parent: object) -> list:
        column_widths = [0] * len(parent.winfo_children())
        for i in range(len(column_widths)):
            ordinal = i
            if ordinal >= len(parent.get_children()):
                break
            component = parent.winfo_children()[ordinal]
            d = int(component.cget('height'))
            column_widths[i] = max(column_widths[i], d)
        return column_widths

    def get_maximized_count(self) -> int:
        count = 0
        for i in range(len(self.maximized_columns)):
            if self.maximized_columns[i]:
                count += 1
        return count


def main():
    layout_manager = MaximizeSpecificColumnGridLayout(3)
    # Add components to the parent container here...
    print(layout_manager.preferred_layout_size(None))


if __name__ == "__main__":
    main()
```

This Python code defines a `MaximizeSpecificColumnGridLayout` class that implements a row-oriented grid type of layout. It lays out rows of information in a table format using a specific number of columns, and allows you to indicate which column should be maximized (i.e., kept at its preferred size) as the parent container is resized.

The code includes methods for calculating the preferred and minimum sizes of the layout, laying out components within the grid, getting the desired widths of individual columns, and determining whether a given column has been maximized.