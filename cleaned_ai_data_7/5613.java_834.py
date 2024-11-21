class ScrollpaneAlignedHorizontalLayout:
    def __init__(self, scroller):
        self.scroller = scroller

    def add_layout_component(self, name, comp):
        # do nothing
        pass

    def remove_layout_component(self, comp):
        # do nothing
        pass

    def layout_container(self, parent):
        viewport_border_bounds = self.scroller.get_viewport_border_bounds()
        n = len(parent.components)
        insets = parentInsets(parent)
        height = viewport_border_bounds.height

        x = insets.left
        y = viewport_border_bounds.y + get_field_header_offset()

        for i in range(n):
            c = parent.components[i]
            width = c.get_preferred_size().width
            if i == n - 1:  # the last gets the remaining width
                width = max(width, parent.width - insets.right - x)
            c.set_bounds(x, y, width, height)
            x += width

    def get_field_header_offset(self):
        comp = self.scroller
        while True:
            if isinstance(comp.parent, FieldHeader):
                return comp.get_y()
            comp = comp.parent
        return 0

    def minimum_layout_size(self, parent):
        return (0, 0)

    def preferred_layout_size(self, parent):
        insets = parentInsets(parent)
        n = len(parent.components)
        height = 0
        width = 0

        for i in range(n):
            c = parent.components[i]
            d = c.get_preferred_size()
            width += d.width
            height = max(height, d.height)

        return (width + insets.left + insets.right, height + insets.top + insets.bottom)


def parentInsets(parent):
    if hasattr(parent, 'get_insets'):
        return parent.get_insets()
    else:
        return (0, 0, 0, 0)
