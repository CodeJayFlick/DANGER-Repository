class AnchoredLayout:
    def __init__(self, layout: 'Layout', index: int, y_pos: int):
        self.layout = layout
        self.index = index
        self.y_pos = y_pos

    @property
    def y_pos(self) -> int:
        return self._y_pos

    @y_pos.setter
    def y_pos(self, value: int) -> None:
        self._y_pos = value

    @property
    def index(self) -> int:
        return self._index

    @index.setter
    def index(self, value: int) -> None:
        self._index = value

    def paint(self, c, g, context, rect, layout_selection_map, cursor_location):
        g.translate(0, self.y_pos)
        rect.y -= self.y_pos
        try:
            self.layout.paint(c, g, context, rect, layout_selection_map, cursor_location)
        finally:
            g.translate(0, -self.y_pos)
            rect.y += self.y_pos

    def get_height(self) -> int:
        return self.layout.get_height()

    def get_compressable_width(self) -> int:
        return self.layout.get_compressable_width()

    def get_scrollable_unit_increment(self, y: int, direction: int) -> int:
        return self.layout.get_scrollable_unit_increment(y, direction)

    @property
    def end_y(self) -> int:
        return self.y_pos + self.layout.get_height()

    def __str__(self):
        return f"{self.index} (ypos = {self.y_pos})"

    def contains(self, y: int) -> bool:
        if yPos >= self.y_pos and y < self.y_pos + self.layout.get_height():
            return True
        return False

    def cursor_beginning(self, cursor_loc):
        return self.layout.cursor_beginning(cursor_loc)

    def cursor_down(self, cursor_loc, last_x):
        return self.layout.cursor_down(cursor_loc, last_x)

    def cursor_end(self, cursor_loc):
        return self.layout.cursor_end(cursor_loc)

    def cursor_left(self, cursor_loc):
        return self.layout.cursor_left(cursor_loc)

    def cursor_right(self, cursor_loc):
        return self.layout.cursor_right(cursor_loc)

    def cursor_up(self, cursor_loc, last_x):
        return self.layout.cursor_up(cursor_loc, last_x)

    def enter_layout(self, cursor_loc, last_x, from_top):
        cursor_loc.set_index(self.index)
        return self.layout.enter_layout(cursor_loc, last_x, from_top)

    def get_begin_row_field_num(self, field1: int) -> int:
        return self.layout.get_begin_row_field_num(field1)

    def get_cursor_rect(self, field_num: int, row: int, col: int):
        rect = self.layout.get_cursor_rect(field_num, row, col)
        if rect is None:
            rect = Rectangle(4, 4)
        rect.y += self.y_pos
        return rect

    def get_end_row_field_num(self, field2: int) -> int:
        return self.layout.get_end_row_field_num(field2)

    def get_field(self, field_index):
        try:
            return self.layout.get_field(field_index)
        except RuntimeError as e:
            if (field_index < 0 or field_index >= self.layout.num_fields()):
                return None
            raise e

    def get_field_bounds(self, field_index: int) -> Rectangle:
        r = self.layout.get_field_bounds(field_index)
        r.y += self.y_pos
        return r

    @property
    def index_size(self):
        return self.layout.index_size()

    @property
    def num_fields(self):
        return self.layout.num_fields()

    @property
    def primary_offset(self) -> int:
        return self.layout.primary_offset()

    def insert_space_above(self, size: int) -> None:
        self.layout.insert_space_above(size)

    def insert_space_below(self, size: int) -> None:
        self.layout.insert_space_below(size)

    def set_cursor(self, cursor_loc, x, y):
        cursor_loc.set_index(self.index)
        return self.layout.set_cursor(cursor_loc, x, y - self.y_pos)
