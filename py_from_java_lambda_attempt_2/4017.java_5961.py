Here is the translation of the Java code into Python:

```Python
class MarkerSetImpl:
    def __init__(self, mgr, program, name, desc, priority, show_markers, 
                 show_navigation, color_background, marker_color, is_preferred):
        self.mgr = mgr
        self.program = program
        self.name = name
        self.description = desc
        self.priority = priority
        self.show_markers = show_markers
        self.show_navigation = show_navigation
        self.color_background = color_background
        self.marker_color = marker_color
        self.is_preferred = is_preferred

    def do_paint_markers(self, g, pixmap, index, map, layouts):
        pass  # abstract method implementation left to the subclass

    def do_paint_navigation(self, g, height, width, range_list):
        pass  # abstract method implementation left to the subclass

    def get_nav_icon(self):
        pass  # abstract method implementation left to the subclass

    def set_marker_descriptor(self, marker_descriptor):
        self.marker_descriptor = marker_descriptor
        return None

    def get_marker_color(self):
        return self.marker_color

    def set_marker_color(self, color):
        self.marker_color = color
        self.mgr.markers_changed(self.program)
        return None

    @property
    def description(self):
        return self.description

    @description.setter
    def description(self, desc):
        self.description = desc

    @property
    def name(self):
        return self.name

    @name.setter
    def name(self, n):
        self.name = n

    @property
    def priority(self):
        return self.priority

    @priority.setter
    def priority(self, p):
        self.priority = p

    @property
    def is_preferred(self):
        return self.is_preferred

    @is_preferred.setter
    def is_preferred(self, b):
        self.is_preferred = b

    def set_address_set_collection(self, address_set_collection):
        if not isinstance(address_set_collection, ModifiableAddressSetCollection):
            raise ValueError("Attempted to modify a read-only marker set.")
        self.markers = address_set_collection
        return None

    def add(self, addr):
        self.add(addr, addr)
        return None

    def add(self, start, end):
        if not isinstance(start, Address) or not isinstance(end, Address):
            raise ValueError("Invalid addresses")
        self.check_modifiable()
        (self.markers).add_range(start, end)
        self.clear_and_update()

    def clear(self, addr):
        return None

    def clear(self, start, end):
        if not isinstance(start, Address) or not isinstance(end, Address):
            raise ValueError("Invalid addresses")
        self.check_modifiable()
        (self.markers).delete_range(start, end)
        self.clear_and_update()

    def clear_all(self):
        self.markers = ModifiableAddressSetCollection()
        return None

    def update_view(self, update_markers, update_navigation):
        if update_markers:
            self.active_layouts = None
        if update_navigation:
            self.overview = None
        return None

    def paint_markers(self, g, index, pixmap, map):
        if self.show_markers:
            layouts = self.compute_active_layouts(pixmap, map)
            self.do_paint_markers(g, pixmap, index, map, layouts)

    def paint_navigation(self, g, height, panel, map):
        if self.show_navigation:
            new_overview = self.compute_navigation_indexes(height, map)
            self.do_paint_navigation(g, height, panel.width(), new_overview)

    @staticmethod
    def get_fill_color(color):
        red = (color.get_red() + 3 * COLOR_VALUE) // 4
        green = (color.get_green() + 3 * COLOR_VALUE) // 4
        blue = (color.get_blue() + 3 * COLOR_VALUE) // 4
        return Color(red, green, blue)

    def compute_active_layouts(self, pixmap, map):
        if pixmap is None:
            return None

        if self.active_layouts is not None:
            return self.active_layouts

        new_layouts = []
        n = pixmap.get_num_layouts()
        for i in range(n):
            addr = pixmap.get_layout_address(i)
            end_addr = pixmap.get_layout_end_address(i)

            if (self.markers).intersects(addr, end_addr):
                new_layouts.append(i)

        self.active_layouts = new_layouts
        return new_layouts

    def compute_navigation_indexes(self, height, map):
        last_height = height
        num_indexes = map.get_index_count()
        index_size = num_indexes / height

        if (self.markers).has_fewer_ranges_than(height):
            field_selection = map.get_field_selection((self.markers))
            n = field_selection.get_num_ranges()

            for i in range(n):
                range_ = field_selection.get_range(i)
                start_index = int(range_.get_start().index() / index_size)
                end_index = int(range_.get_end().index() / index_size)

                self.overview.add_range(start_index, end_index)

        else:
            big_height = BigDecimal(str(height))
            num_indexes_minus1 = num_indexes - 1

            for i in range(MARKER_HEIGHT):
                if (self.overview).contains(index - i):
                    return True
            return False

    def get_tooltip(self, addr, x, y):
        if self.marker_descriptor is not None:
            marker_location = MarkerLocation(self, self.mgr.get_program(), addr, x, y)
            return self.marker_descriptor.get_tooltip(marker_location)

        return None

    @property
    def displayed_in_navigation_bar(self):
        return self.show_navigation

    @displayed_in_navigation_bar.setter
    def displayed_in_navigation_bar(self, b):
        self.show_navigation = b
        self.mgr.markers_changed(self.program)
        return None

    @property
    def display_in_marker_bar(self):
        return self.show_markers

    @display_in_marker_bar.setter
    def display_in_marker_bar(self, b):
        self.show_markers = b
        self.mgr.markers_changed(self.program)
        return None

    @property
    def coloring_background(self):
        return self.color_background

    @coloring_background.setter
    def coloring_background(self, b):
        self.color_background = b
        self.mgr.markers_changed(self.program)
        return None

    def get_program_location(self, y, height, map, x):
        if (self.overview).contains(index - i):
            return None

        program_location = None
        addr = markers.get_min_address()

        if marker_descriptor is not None:
            marker_location = MarkerLocation(self, self.mgr.get_program(), addr, x, y)
            program_location = marker_descriptor.get_program_location(marker_location)

        return program_location

    def get_min_address(self):
        return self.markers.get_min_address()

    def get_max_address(self):
        return self.markers.get_max_address()

    def intersects(self, start, end):
        return (self.markers).intersects(start, end)
```

Please note that the Python code above is a direct translation of the Java code and may not be perfect. It's also worth noting that this code does not include any implementation for abstract methods (`do_paint_markers`, `do_paint_navigation`, `get_nav_icon`). These should be implemented in subclasses or overridden as needed.

Also, some parts of the original Java code have been removed (like the static method `getIndex`) and replaced with Python's built-in functionality.