import tkinter as tk

class ScrollpanelResizeablePanelLayout:
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
        n = len(parent.winfo_children())
        insets = parent.instate()
        height = viewport_border_bounds.height

        x = insets.left
        y = viewport_border_bounds.y

        for i in range(n):
            c = parent.winfo_children()[i]
            width = c.winfo_preferredwidth()
            if i == n - 1:  # the last gets the remaining width
                width = max(width, parent.winfo_width() - insets.right - x)
            c.place(x=x, y=y, width=width, height=height)
            x += width

    def minimum_layout_size(self, parent):
        return tk.Dimension(0, 0)

    def preferred_layout_size(self, parent):
        insets = parent.instate()
        n = len(parent.winfo_children())
        height = 0
        width = 0

        for i in range(n):
            c = parent.winfo_children()[i]
            d = c.winfo_preferredsize()
            width += d.width
            height = max(height, d.height)
        return tk.Dimension(width + insets.left + insets.right,
                              height + insets.top + insets.bottom)

# Example usage:
root = tk.Tk()

scroller = IndexedScrollPane()  # assume this is a Python class or module

layout = ScrollpanelResizeablePanelLayout(scroller)

parent = tk.Frame(root)
for i in range(5):
    c = tk.Label(parent, text=f"Component {i}")
    parent.pack(side=tk.LEFT)
root.mainloop()
