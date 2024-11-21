Here is a translation of the Java code into equivalent Python:

```Python
import tkinter as tk
from tkinter import scrolledtext
from tkinter import ttk

class IndexedScrollPane:
    def __init__(self, comp):
        self.comp = comp
        if not isinstance(comp, IndexedScrollable):
            raise ValueError("component must implement IndexedScrollable interface.")
        
        self.scrollable = comp
        self.scrollable.add_index_scroll_listener(self)
        self.setLayout(tk.FrameLayout())
        self.view_component = tk.Frame()
        self.view_component.pack(fill=tk.BOTH, expand=True)

    def set_never_scroll(self, b):
        self.never_scroll = True
        self.scrollpane.set_vertical_scrollbar_policy(0)
        self.scrollpane.set_horizontal_scrollbar_policy(0)
        self.use_view_size_as_preferred_size = b

    def create_index_mapper(self):
        if self.never_scroll:
            return PreMappedViewToIndexMapper(self.scrollable)

        num_indexes = self.scrollable.get_index_count()
        if num_indexes == 0:
            return UniformViewToIndexMapper(self.scrollable)
        
        if self.scrollable.is_uniform_index():
            layout_height = self.scrollable.get_height(0)
            total_scroll_height = num_indexes * BigInteger.valueOf(layout_height)
            if total_scroll_height < BigInteger.valueOf(int.max_value):
                return UniformViewToIndexMapper(self.scrollable)

        if num_indexes < 1000:
            return PreMappedViewToIndexMapper(self.scrollable)
        
        return DefaultViewToIndexMapper(self.scrollable, self.viewport.get_extent_size().height)

    def get_view_size(self):
        return Dimension(self.comp.get_preferred_size().width, self.index_mapper.get_view_height())

    def viewport_state_changed(self):
        extent_size = self.viewport.get_extent_size()
        if not extent_size.equals(self.visible_size):
            self.visible_size = extent_size
            self.index_mapper.set_visible_view_height(extent_size.height)
            self.comp.invalidate()
            self.repaint()

        view_position = self.viewport.get_view_position()
        if self.vertical_offset != view_position.y:
            self.vertical_offset = view_position.y
            self.comp.move(0, self.vertical_offset)

    def index_range_changed(self, start_index, end_index, y_start, y_end):
        self.programatically_adjusting_scrollbar = True

        try:
            scroll_value = self.index_mapper.get_scroll_value(start_index, end_index, y_start, y_end)
            p = self.viewport.get_view_position()
            if p.y != scroll_value:
                self.viewport.set_view_position(tk.Point(p.x, scroll_value))

        finally:
            self.programatically_adjusting_scrollbar = False

    def index_model_changed(self):
        self.index_mapper = self.create_index_mapper()
        self.viewport.do_layout()

    def index_model_data_changed(self, start_index, end_index):
        self.index_mapper.index_model_data_changed(start_index, end_index)
        self.comp.invalidate()
        self.viewport.do_layout()


class ScrollViewLayout:
    def add_layout_component(self, name, comp):
        pass

    def layout_container(self, parent):
        self.comp.set_bounds(0, self.vertical_offset, parent.size.width, self.visible_size.height)

    def minimum_layout_size(self, parent):
        return preferred_layout_size(parent)

    def preferred_layout_size(self, parent):
        comp_preferred_size = self.comp.get_preferred_size()
        height = max(self.index_mapper.get_view_height(), self.visible_size.height)
        view_width = comp_preferred_size.width
        return tk.Dimension(view_width, height)


class ScrollView(tk.Frame, Scrollable):
    def __init__(self, component):
        super().__init__()
        self.component = component
        self.setLayout(ScrollViewLayout())
        self.add(component)

    def get_preferred_scrollableViewport_size(self):
        preferred_height = 500 if not self.use_view_size_as_preferred_size else self.index_mapper.get_view_height()
        view_width = self.comp.get_preferred_size().width
        return tk.Dimension(view_width, preferred_height)


class SideKickVerticalScrollbar:
    pass


# You will need to implement the following classes in Python:

class PreMappedViewToIndexMapper:
    def __init__(self, scrollable):
        super().__init__()
        self.scrollable = scrollable

    # Implement other methods here...

class UniformViewToIndexMapper:
    def __init__(self, scrollable):
        super().__init__()
        self.scrollable = scrollable

    # Implement other methods here...



# You will need to implement the following classes in Python:

class DefaultViewToIndexMapper:
    def __init__(self, scrollable, view_height):
        super().__init__()
        self.scrollable = scrollable
        self.view_height = view_height

    # Implement other methods here...

```

Please note that this is a direct translation of the Java code into Python. It may not work as expected without proper testing and debugging.

Also, you will need to implement some classes (`PreMappedViewToIndexMapper`, `UniformViewToIndexMapper`, `DefaultViewToIndexMapper`) in your Python code which are missing from above code snippet.