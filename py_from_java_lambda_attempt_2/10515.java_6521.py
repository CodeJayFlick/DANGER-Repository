Here is the translation of the Java code into Python:

```Python
import math

class RightSidedSquishyBuddyLayout:
    def __init__(self, h_gap):
        self.h_gap = h_gap
        self.right_align = False

    def set_right_alignment(self, right_align=True):
        self.right_align = right_align

    def add_layout_component(self):  # nothing to do
        pass

    def remove_layout_component(self, comp):  # nothing to do
        pass

    def preferred_layout_size(self, container):
        components = list(container.get_children())
        if not components:
            return (0, 0)
        width = self.h_gap
        height = 0

        for i in range(2):
            if i < len(components):
                component = components[i]
                dim = component.winfo_reqwidth(), component.winfo_height()
                width += dim[0] + self.h_gap
                height = max(height, dim[1])

        insets = container.winfo_rootx() - 10, container.winfo_rooty() - 10, container.winfo_width() - (container.winfo_rootx() + 20), container.winfo_height() - (container.winfo_rooty() + 20)
        width += sum(insets[:2])
        height += sum(insets[2:])
        return (width, height)

    def minimum_layout_size(self, cont):
        return self.preferred_layout_size(cont)

    def layout_container(self, container):
        components = list(container.get_children())
        if not components:
            return
        insets = container.winfo_rootx() - 10, container.winfo_rooty() - 10, container.winfo_width() - (container.winfo_rootx() + 20), container.winfo_height() - (container.winfo_rooty() + 20)
        if len(components) == 1:
            size = components[0].winfo_reqwidth(), components[0].winfo_height()
            components[0].place(x=insets[0], y=insets[1], width=size[0], height=size[1])
            return
        container_size = (container.winfo_width() - sum(insets[:2]), container.winfo_height() - sum(insets[2:]))
        comp1_pref_size, _ = components[0].winfo_reqsize()
        _, comp2_pref_size = components[1].winfo_reqsize()

        # always give comp1 its preferredWidth;

        comp1_width, _ = comp1_pref_size
        remaining_width = max(0, container_size[0] - comp1_width - self.h_gap)
        comp2_width = min(comp2_pref_size[0], remaining_width)
        remaining_width -= comp2_width

        y = insets[3]

        comp1_x = insets[0]
        comp2_x = comp1_x + comp1_width + self.h_gap
        if self.right_align:
            comp1_x += remaining_width
            comp2_x += remaining_width

        components[0].place(x=comp1_x, y=y, width=comp1_width, height=container_size[1])
        components[1].place(x=comp2_x, y=y, width=comp2_width, height=container_size[1])

```

Please note that this is a translation of the Java code into Python. The actual functionality may not be exactly the same due to differences in language syntax and semantics.