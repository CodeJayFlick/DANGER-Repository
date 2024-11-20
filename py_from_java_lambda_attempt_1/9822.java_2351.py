Here's your Java code translated into Python:

```Python
import tkinter as tk
from typing import Optional

class GTableMouseListener:
    def __init__(self, table: 'GTable'):
        self.table = table
        self.is_dragged = False  # prevents popups during drag operations
        self.is_popup = False  # prevents sorting during popups
        self.sorting_enabled = True

    def set_sorting_enabled(self, enabled: bool):
        self.sorting_enabled = enabled

    def mouse_pressed(self, e: 'MouseEvent'):
        if not e.popup_trigger:
            return

        self.process_popup(e)

    def mouse_released(self, e: 'MouseEvent'):
        if not e.popup_trigger:
            self.is_dragged = False  # allow popups to show since dragging is finished
            return

        self.process_popup(e)

    def process_popup(self, e):
        if not self.is_dragged:

            if self.should_ignore_right_click():
                return

            column_index = self.table.column_at_point(e.point)
            menu = self.table.get_table_column_menu(column_index)
            if menu:
                self.is_popup = True
                menu.show(e.component, e.x, e.y)
            else:
                e.consume()

        else:
            self.is_dragged = False  # allow popups to show since dragging is finished

    def mouse_clicked(self, e):
        was_popup = self.is_popup
        self.is_popup = False
        if e.consumed or was_popup:
            return

        column_model = self.table.get_column_model()
        col_index = column_model.column_at_x(e.x)
        if col_index < 0:
            return

        if self.is_help_click():
            # show help here, for example with tkinter.messagebox.showinfo
            pass

        if not self.sorting_enabled:
            return

        if e.control_modifier:
            TableUtils.column_alternatively_selected(self.table, col_index)
        else:
            TableUtils.column_selected(self.table, col_index)

    def mouse_dragged(self, e):
        self.is_dragged = True

    def is_help_click(self) -> bool:
        table_header = self.table.get_table_header()
        if not isinstance(table_header, GTableHeader):
            return False
        tooltip_table_header = GTableHeader(table_header)
        return tooltip_table_header.mouse_over_help_icon()

    def should_ignore_right_click(self) -> bool:
        return self.is_help_click()


class TableUtils:
    @staticmethod
    def column_selected(table: 'GTable', col_index: int):
        pass

    @staticmethod
    def column_alternatively_selected(table: 'GTable', col_index: int):
        pass


# tkinter equivalent of JPopupMenu
class GTableColumnMenu(tk.Menu):
    pass


# tkinter equivalent of JTableHeader
class GTableHeader:
    def __init__(self, table_header):
        self.table_header = table_header

    @property
    def mouse_over_help_icon(self) -> bool:
        return False  # implement this method in your subclass


class GTable:
    pass

# tkinter equivalent of JTableColumnModel
class TableColumnModel:
    pass

# tkinter equivalent of TableColumnModel (for column index at x)
def get_column_model(table: 'GTable') -> Optional[TableColumnModel]:
    return None  # implement this method in your subclass


# tkinter equivalent of GTableColumnModel
class GTableColumnModel(TableColumnModel):
    def save_state(self) -> None:
        pass

    @property
    def column_at_x(self, x: int) -> int:
        return -1  # implement this method in your subclass

    @property
    def get_column_model(self) -> Optional[TableColumnModel]:
        return None  # implement this method in your subclass


# tkinter equivalent of DockingWindowManager and its methods
class DockingWindowManager:
    @staticmethod
    def get_help_service() -> 'HelpService':
        pass

    @staticmethod
    def register_help(cls, help_location):
        pass

    @staticmethod
    def show_help(cls, is_popup: bool, table: 'GTable'):
        pass


# tkinter equivalent of HelpLocation and its methods
class HelpLocation:
    pass


# tkinter equivalent of MouseAdapter and MouseEvent
class MouseAdapter:
    pass


class MouseEvent:
    def __init__(self):
        self.popup_trigger = False

    @property
    def is_popup_trigger(self) -> bool:
        return self.popup_trigger

    @property
    def get_point(self) -> tuple[int, int]:
        return (0, 0)

    @property
    def component(self) -> 'tk.Widget':
        pass

    @property
    def x(self) -> int:
        return 0

    @property
    def y(self) -> int:
        return 0


# tkinter equivalent of DockingUtils and its methods
class DockingUtils:
    @staticmethod
    def is_control_modifier(e: 'MouseEvent') -> bool:
        pass


if __name__ == "__main__":
    root = tk.Tk()
    table = GTable()  # implement this class in your subclass

    mouse_listener = GTableMouseListener(table)
    root.bind("<Button-1>", lambda e: mouse_listener.mouse_clicked(e))
    root.bind("<Motion>", lambda e: mouse_listener.mouse_dragged(e))

    root.mainloop()

```

Please note that you will need to create the missing classes (`GTable`, `GTableHeader`, etc.) and implement their methods according to your needs.