Here is the translation of the Java code into Python:

```Python
class VariableHeightPairLayout:
    def __init__(self):
        self.vgap = 0
        self.hgap = 0
        self.preferredWidth2 = 80

    def add_layout_component(self, name, comp): pass

    def remove_layout_component(self, comp): pass

    def preferred_layout_size(self, parent):
        d = [0, 0]
        insets = parent.getInsets()
        widths = self.get_preferred_widths(parent)
        d[0] += widths[0] + self.hgap
        d[1] = widths[1]
        n = len(parent.components())
        for i in range(0, n, 2):
            c = parent.component(i)
            height = c.getPreferredSize()[1]
            if i < n - 1:
                c = parent.component(i + 1)
                height = max(height, c.getPreferredSize()[1])
            d[1] += height
            d[1] += self.vgap
        d[1] -= self.vgap
        return tuple(d)

    def minimum_layout_size(self, parent):
        return self.preferred_layout_size(parent)

    def layout_container(self, parent):
        widths = self.get_preferred_widths(parent)
        d = parent.getSize()
        insets = parent.getInsets()
        width = d[0] - (insets[0] + insets[2])
        x = 0
        y = 0
        n_rows = len(parent.components())
        for i in range(0, n_rows, 2):
            c = parent.component(i)
            height = c.getPreferredSize()[1]
            if i < n_rows - 1:
                c2 = parent.component(i + 1)
                height = max(height, c2.getPreferredSize()[1])
                c2.setBounds(x + widths[0] + self.hgap, y, width - (widths[0] + self.hgap), height)
            else:
                c.setBounds(0, y, widths[0], height)
            y += height
            if i < n_rows - 1:
                y += self.vgap

    def get_preferred_widths(self, parent):
        widths = [self.preferredWidth2]
        for component in parent.components():
            d = component.getPreferredSize()
            index = len(parent.components()) % 2
            widths[index] = max(widths[index], d[0])
        return tuple(widths)
```

Please note that Python does not have direct equivalent of Java's `LayoutManager`, so the code is translated to a class with methods for layout management.