import tkinter as tk


class MiddleLayout:
    def __init__(self):
        pass

    def add_layout_component(self, name, comp):
        # nothing to do
        return None

    def remove_layout_component(self, comp):
        # nothing to do
        return None

    def preferred_layout_size(self, container):
        components = list(container.winfo_children())
        if not components:
            return tk.Size(0, 0)
        
        component = components[0]
        if component is None:
            return tk.Size(0, 0)  # shouldn't happen
        
        size = component.get_width() + 2 * container.winfo_xscrollbar().get_width()
        height = component.get_height() + 2 * container.winfo_yscrollbar().get_height()

        if hasattr(container, 'winfo_rootx'):
            x = (container.winfo_rootx() - min(c.winfo_rootx() for c in components) +
                 max((c.winfo_width() / 2) for c in components))
            y = ((container.winfo_yroot() - min(c.winfo_yroot() for c in components)) +
                 max((c.get_height() / 2) for c in components))

        else:
            x, y = (0, 0)

        return tk.Size(x + container.winfo_rootx(), y + container.winfo_yroot())

    def minimum_layout_size(self, cont):
        return self.preferred_layout_size(cont)


class Container(tk.Frame):

    def __init__(self, master=None):
        super().__init__(master)
        if master:
            self.pack()
        else:
            self.mainloop()

    def get_components(self):
        return list(self.winfo_children())

    def set_size(self, width, height):
        self.config(width=width, height=height)

    def get_size(self):
        return tk.Size(int(self.cget('width')), int(self.cget('height')))


class Size:
    def __init__(self, width, height):
        self.width = width
        self.height = height

    @property
    def x(self):
        return 0

    @property
    def y(self):
        return 0


def main():
    root = tk.Tk()
    container = Container(root)
    
    component1 = tk.Frame(container, bg='blue', width=100, height=50)
    component2 = tk.Frame(container, bg='red', width=200, height=75)

    for comp in [component1, component2]:
        comp.pack()

    layout_manager = MiddleLayout()
    container.layout(layout_manager)


if __name__ == "__main__":
    main()
