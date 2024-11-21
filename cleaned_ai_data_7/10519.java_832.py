class TwoColumnPairLayout:
    def __init__(self):
        self.vertical_gap = 0
        self.column_gap = 0
        self.pair_gap = 0
        self.preferred_column_width = 0

    def add_layout_component(self, name, comp):
        pass

    def remove_layout_component(self, comp):
        pass

    def preferred_layout_size(self, parent):
        row_height = get_preferred_row_height(parent)
        widths = get_preferred_widths(parent)

        n_rows = (parent.get_component_count() + 3) // 4
        insets = parent.get_insets()
        d = Dimension(0, 0)

        if self.preferred_column_width > 0:
            widths[1] = widths[3] = self.preferred_column_width

        d.width = sum(widths[:]) + self.column_gap * 2 + self.pair_gap * 2 + insets.left + insets.right
        d.height = row_height * n_rows + self.vertical_gap * (n_rows - 1) + insets.top + insets.bottom
        return d

    def minimum_layout_size(self, parent):
        return self.preferred_layout_size(parent)

    def layout_container(self, parent):
        row_height = get_preferred_row_height(parent)
        widths = get_preferred_widths(parent)

        d = parent.get_size()
        insets = parent.get_insets()
        width = d.width - (insets.left + insets.right)
        x = 0
        y = 0

        total_label_width = sum(widths[:2])
        padding = self.pair_gap * 2 + self.column_gap
        total_value_width = width - total_label_width - padding

        widths[1] = int((total_value_width / (widths[1] + widths[3])) * widths[1])
        widths[3] = total_value_width - widths[1]

        n_components = parent.get_component_count()
        for i in range(n_components):
            index = i % 4
            c = parent.get_component(i)
            c.set_bounds(x, y, widths[index], row_height)
            x += widths[index]
            if index == 1:
                x += self.column_gap
            else:
                x += self.pair_gap

            if (i + 1) % 4 == 0:
                y += row_height + self.vertical_gap
                x = 0


    def get_preferred_row_height(self, parent):
        height = 0
        n_components = parent.get_component_count()
        for i in range(n_components):
            c = parent.get_component(i)
            height = max(height, c.get_preferred_size().height)
        return height

    def get_preferred_widths(self, parent):
        widths = [0] * 4
        n_components = parent.get_component_count()
        for i in range(n_components):
            c = parent.get_component(i)
            d = c.get_preferred_size()
            index = i % 4
            widths[index] = max(widths[index], d.width)
        return widths


class Dimension:
    def __init__(self, width, height):
        self.width = width
        self.height = height

    @property
    def size(self):
        return (self.width, self.height)

    def get_size(self):
        return self.size
