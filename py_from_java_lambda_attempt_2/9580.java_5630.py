Here is the translation of the Java interface `Layout` into a Python class:

```Python
class Layout:
    def __init__(self):
        pass

    def get_height(self):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def get_primary_offset(self):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def insert_space_above(self, size):
        # implement this method in your subclass
        pass

    def insert_space_below(self, size):
        # implement this method in your subclass
        pass

    def get_num_fields(self):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def get_field(self, index):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def paint(self, c, g, context, rect, layout_color_map, cursor_location):
        # implement this method in your subclass
        pass

    def set_cursor(self, cursor_loc, x, y):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def get_cursor_rect(self, field_num, row, col):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def cursor_up(self, cursor_loc, last_x):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def cursor_down(self, cursor_loc, last_x):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def cursor_beginning(self, cursor_loc):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def cursor_end(self, cursor_loc):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def cursor_left(self, cursor_loc):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def cursor_right(self, cursor_loc):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def enter_layout(self, cursor_loc, last_x, from_top):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def get_scrollable_unit_increment(self, top_of_screen, direction):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def contains(self, y_pos):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def get_field_bounds(self, index):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def get_index_size(self):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def get_begin_row_field_num(self, field1):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def get_end_row_field_num(self, field2):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def get_compressable_width(self):
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")
```

Note that I've left the methods as `raise NotImplementedError("Method not implemented")`, which means you'll need to define these methods in any subclasses of `Layout`.