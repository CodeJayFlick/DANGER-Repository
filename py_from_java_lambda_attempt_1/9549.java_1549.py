Here is your Java code translated into Python:

```Python
class SimpleImageField:
    def __init__(self, icon, metrics, start_x, start_y, width):
        self.height_above = metrics.get_max_ascent() + metrics.get_leading()
        self.height = self.height_above + metrics.get_max_descent()

        self.icon = icon
        self.metrics = metrics
        self.start_x = start_x
        self.width = width

    def contains(self, x, y):
        if (x >= self.start_x and x < self.start_x + self.width) and \
           (y >= -self.height_above and y < self.height - self.height_above):
            return True
        return False

    def get_col(self, row, x):
        return 0

    def get_cursor_bounds(self, row, col):
        if row != 0:
            return None
        return Rectangle(self.start_x, -self.height_above, self.width, self.height)

    def get_height(self):
        return self.height

    def get_num_data_rows(self):
        return 1

    def get_num_rows(self):
        return 1

    def get_num_cols(self, row):
        return 1

    def get_row(self, y):
        return 0

    def get_scrollable_unit_increment(self, top_of_screen, direction, max):
        if (top_of_screen < -self.height_above) or (top_of_screen > self.height - self.height_above):
            return max
        if direction > 0:  # if scrolling down
            return self.height - top_of_screen - self.height_above
        return -self.height_above - top_of_screen

    def get_start_x(self):
        return self.start_x

    def get_width(self):
        return self.width

    def get_preferred_width(self):
        return self.icon.get_size()[0]

    def get_x(self, row, col):
        return 0

    def get_y(self, row):
        return -self.height_above

    def is_valid(self, row, col):
        if row != 0:
            return False
        if col != 0:
            return False
        return True

    def paint(self, c, g, context, clip, map, cursor_loc, row_height):
        if self.icon is None:
            return
        tmp_width = self.icon.get_size()[0]
        tmp_height = self.icon.get_size()[1]
        xoffset = 0
        yoffset = 0

        if self.center:
            if self.width > tmp_width:
                xoffset = (self.width - tmp_width) // 2
            if self.height > tmp_height:
                yoffset = (self.height - tmp_height) // 2

        if tmp_width > self.width:
            tmp_width = self.width
        if tmp_height > self.height:
            tmp_height = self.height

        g.draw_image(self.icon, self.start_x + xoffset, -self.height_above + yoffset,
                     tmp_width, tmp_height, self.icon.get_observer())

        if cursor_loc is not None:
            g.set_color(context.get_cursor_color())
            rect = self.get_cursor_bounds(cursor_loc.row(), cursor_loc.col())
            g.draw_rect(rect.x, rect.y, tmp_width - 1, tmp_height - 1)

    def is_primary(self):
        return self.isPrimary

    def set_primary(self, state):
        self.isPrimary = state

    @property
    def height_above(self):
        return self._height_above

    @height_above.setter
    def height_above(self, value):
        self._height_above = value

    @property
    def height_below(self):
        return self.height - self.height_above

    def row_height_changed(self, new_height_above, new_height_below):
        pass  # don't care

    def get_text(self):
        return ""

    def get_text_with_line_separators(self):
        return ""

    def text_offset_to_screen_location(self, text_offset):
        return DefaultRowColLocation()

    def screen_location_to_text_offset(self, row, col):
        return 0
```

Please note that Python does not have direct equivalent of Java's `ImageIcon` and `FontMetrics`. You might need to use a library like Pillow for image handling.