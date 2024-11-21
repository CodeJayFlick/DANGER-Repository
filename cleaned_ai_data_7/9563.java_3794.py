import time
from threading import Timer

class CursorBlinker:
    def __init__(self, field_panel):
        self.field_panel = field_panel
        self.timer = None
        self.show_cursor = False
        self.cursor_position = FieldLocation()
        self.layout = None
        self.paint_bounds = None
        self.layout_ypos = 0

        timer = Timer(500, self.update_timer)
        timer.set_initial_delay(100)
        timer.start()

    def update_timer(self):
        if self.paint_bounds is not None:
            self.show_cursor = not self.show_cursor
            self.field_panel.repaint(self.paint_bounds)
        else:
            self.timer.stop()

    def stop(self):
        if self.timer is not None:
            self.timer.stop()
            self.timer = None

    def restart(self):
        self.timer.restart()

    def dispose(self):
        if self.timer is not None:
            self.timer.stop()
            self.timer = None
        self.field_panel = None

    def update_paint_area(self, cursor_layout, cursor_position):
        if (cursor_layout != self.layout or
                self.layout_ypos != cursor_layout.get ypos() or
                self.cursor_position != cursor_position):
            self.layout = cursor_layout
            self.cursor_position = cursor_position
            self.show_cursor = True
            if self.layout is not None:
                self.layout_ypos = self.layout.get y_pos()
                self.timer.restart()
                self.paint_bounds = self.layout.get_field_bounds(cursor_position.field_num)
            else:
                self.timer.stop()
                self.paint_bounds = None

    def show_cursor(self):
        return self.show_cursor


class FieldLocation:
    pass
