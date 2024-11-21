import math

class RangeCursorTableHeaderRenderer:
    ARROW_SIZE = 10
    ARROW = [(0, 0), (-ARROW_SIZE, ARROW_SIZE), (-ARROW_SIZE, -ARROW_SIZE)]

    def __init__(self):
        self.full_range = (0.0, 1.0)
        self.span = 1

    def set_full_range(self, full_range):
        if not isinstance(full_range[0], (int, float)) or not isinstance(full_range[1], (int, float)):
            raise TypeError("Full range must be a tuple of two numbers")
        self.full_range = full_range
        self.span = self.full_range[1] - self.full_range[0]

    def set_cursor_position(self, pos):
        if not isinstance(pos, (int, float)) or not isinstance(getattr(pos, 'doubleValue', None), (int, float)):
            raise TypeError("Position must be a number")
        self.pos = pos
        self.double_pos = pos.get_double_value()

    def paint_children(self, g):
        super().paint_children(g)
        self.paint_cursor(g)

    def paint_cursor(self, parent_g):
        g = parent_g.create()
        g.set_antialiasing(True)
        x = (self.double_pos - self.full_range[0]) / self.span * parent_g.get_width()
        g.translate(x, parent_g.get_height())
        g.rotate(math.pi/2)
        g.set_color(self.get_foreground())
        g.fill_polygon(self.ARROW)

    def add_seek_listener(self, table, model_column, listener):
        col_model = table.column_model
        header = table.table_header
        column = col_model[model_column]
        l = MouseAdapter()
        l.mouse_clicked = lambda e: self.do_seek(e)
        l.mouse_dragged = lambda e: self.do_seek(e)

    def do_seek(self, e):
        if not isinstance(e, MouseEvent):
            raise TypeError("Event must be a mouse event")
        view_col_idx = e.get_x() // column.get_width()
        model_col_idx = table.convert_column_index_to_model(view_col_idx)
        if model_col_idx != self.model_column:
            return
        col_dragged = header.dragged_column
        if col_dragged == column:
            header.set_dragged_column(None)
        else:
            return

    def get_cursor_position(self):
        return self.pos


class MouseAdapter:
    mouse_clicked = None
    mouse_dragged = None

    def __init__(self, *args, **kwargs):
        pass

    def mouseClicked(self, e):
        if not isinstance(e, MouseEvent) or (e.get_modifiers() & 0x10000) != 0:
            return
        self.mouse_clicked(e)

    def mouseDragged(self, e):
        if not isinstance(e, MouseEvent) and (e.get_modifiers() & 0x40000) == 0:
            return
        self.mouse_dragged(e)
