class OpenCloseField:
    def __init__(self, factory: 'OpenCloseFactory', proxy_obj: ProxyObj, indent_level: int,
                 metrics: FontMetrics, x: int, width: int, is_last: bool):
        self.factory = factory
        self.proxy = proxy_obj
        self.is_open = proxy_obj.get_listing_layout_model().is_open(proxy_obj.get_object())
        self.field_width = width
        self.start_x = x
        self.indent_level = indent_level
        self.is_last = is_last
        self.height_above = metrics.ascent
        self.height_below = metrics.leading + metrics.descent
        self.toggle_handle_size = OpenCloseField._get_open_close_handle_size()

    @property
    def field_factory(self):
        return self.factory

    @property
    def field_model(self):
        return self.factory.field_model

    @property
    def proxy_obj(self):
        if not self.proxy:
            return EmptyProxy.EMPTY_PROXY
        return self.proxy

    @property
    def height_above(self):
        return self._height_above

    @height_above.setter
    def height_above(self, value: int):
        self._height_above = value

    @property
    def height_below(self):
        return self._height_below

    @height_below.setter
    def height_below(self, value: int):
        self._height_below = value

    def set_y_pos(self, y_pos: int, height_above: int, height_below: int) -> None:
        self.start_y = y_pos
        self.height_above = height_above
        self.height_below = height_below

    @property
    def width(self):
        return (self.indent_level + 1) * self.field_width

    @property
    def preferred_width(self):
        return self.width

    @property
    def height(self):
        return self.height_above + self.height_below

    @property
    def start_x(self):
        return self._start_x

    @start_x.setter
    def start_x(self, value: int) -> None:
        self._start_x = value

    @property
    def start_y(self):
        return self._start_y

    @start_y.setter
    def start_y(self, value: int) -> None:
        self._start_y = value

    def paint(self, c: JComponent, g: Graphics, context: PaintContext,
              clip: Rectangle, map: FieldBackgroundColorManager, cursor_loc: RowColLocation,
              row_height: int):
        toggle_handle_start_x = -((self.height_above / 2) + (self.toggle_handle_size / 2))
        toggle_handle_start_y = self.start_y
        if not context.is_printing():
            if self.is_open:
                g.drawImage(self.open_image, toggle_handle_start_x, toggle_handle_start_y,
                            context.get_background(), None)
            else:
                g.drawImage(self.closed_image, toggle_handle_start_x, toggle_handle_start_y,
                            context.get_background(), None)

        g.setColor(Color.LIGHT_GRAY)
        for i in range(1, self.indent_level):
            field_offset = i * self.field_width
            previous_button_start_x = self.start_x + field_offset + 1
            midpoint_x = previous_button_start_x + (self.toggle_handle_size / 2)
            g.drawLine(midpoint_x, -self.height_above, midpoint_x, self.height_below)

        if self.indent_level > 0:
            indent_offset = self.width
            toggle_handle_end_x = toggle_handle_start_x + self.toggle_handle_size
            midpoint_y = toggle_handle_start_y + (self.toggle_handle_size / 2)
            end_x = self.start_x + indent_offset
            g.drawLine(toggle_handle_end_x, midpoint_y, end_x, midpoint_y)

            if not self.is_last and not self.is_open:
                button_bottom_y = toggle_handle_start_y + self.toggle_handle_size
                g.drawLine(midpoint_x, button_bottom_y, midpoint_x, self.height_below)
        else:
            paint_cursor(g, context.get_cursor_color(), cursor_loc)

    def paint_cursor(self, g: Graphics, color: Color, loc: RowColLocation) -> None:
        if loc is not None:
            g.setColor(color)
            bounds = get_cursor_bounds(loc.row, loc.col())
            g.fillRect(bounds.x, bounds.y, bounds.width, bounds.height)

    def contains(self, x: int, y: int):
        return (x >= self.start_x and
                x < self.start_x + self.field_width and
                y >= self.start_y and
                y < self.start_y + self.height_above + self.height_below)

    @property
    def num_data_rows(self) -> int:
        return 1

    @property
    def num_rows(self):
        return 1

    @property
    def num_cols(self, row: int) -> int:
        return 0

    @property
    def x(self, row: int, col: int) -> int:
        return self.start_x

    @property
    def y(self, row: int) -> int:
        return self.start_y

    @property
    def row(self, y: int) -> int:
        return 0

    @property
    def col(self, row: int, x: int) -> int:
        return 0

    def is_valid(self, row: int, col: int):
        return (row == 0 and col == 0)

    def get_cursor_bounds(self, row: int, col: int) -> Rectangle:
        if not self.is_valid(row, col):
            return None
        return Rectangle(self.start_x - self.height_above,
                          -self.height_above,
                          2,
                          self.height_above + self.height_below)

    @property
    def is_primary(self) -> bool:
        return False

    def row_height_changed(self, new_height_above: int, new_height_below: int):
        self.height_above = new_height_above
        self.height_below = new_height_below

    @property
    def text(self) -> str:
        return ""

    @property
    def text_with_line_separators(self) -> str:
        return ""

    def text_offset_to_screen_location(self, offset: int):
        return DefaultRowColLocation()

    def screen_location_to_text_offset(self, row: int, col: int) -> int:
        return 0

    @property
    def clicked_object(self, field_loc: FieldLocation) -> object:
        return self

    def toggle_open_close_state(self) -> None:
        self.proxy.get_listing_layout_model().toggle_open(self.proxy.get_object())

@staticmethod
def _get_open_close_handle_size():
    return OpenCloseField.open_image.get_icon_width()
