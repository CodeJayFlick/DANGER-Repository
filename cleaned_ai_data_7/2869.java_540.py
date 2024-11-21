import tkinter as tk
from typing import Any, Callable, ClassVar, Generic, TypeGuard

class MyRow:
    def __init__(self, name: str, lifespan: range) -> None:
        self.name = name
        self.lifespan = lifespan

    @property
    def name(self) -> str:
        return self.name

    @name.setter
    def name(self, value: str) -> None:
        self.name = value

    @property
    def lifespan(self) -> range:
        return self.lifespan

    @lifespan.setter
    def lifespan(self, value: range) -> None:
        self.lifespan = value

class MyColumns(Generic[MyRow]):
    NAME = "Name", str, lambda row: row.name
    LIFESPAN = "Lifespan", range, lambda row: row.lifespan

def test_demo_range_cell_renderer() -> None:
    root = tk.Tk()
    root.title("People")

    model = DefaultEnumeratedColumnTableModel(MyColumns)
    table = GhidraTable(model)

    column = table.column_model.get_column(1)  # Assuming the lifespan is in second column
    range_renderer = RangeTableCellRenderer(range(1800, 2000))
    header_renderer = RangeCursorTableHeaderRenderer(range(1800, 2000), pos=1940)
    column.set_cell_renderer(range_renderer)
    column.set_header_renderer(header_renderer)

    model.add(MyRow("Albert", range(1879, 1955)))
    model.add(MyRow("Bob", range(1956, float('inf'))))
    model.add(MyRow("Elvis", range(1935, 1977)))

    def on_seek(pos: int) -> None:
        print(f"pos: {pos}")
        header_renderer.set_cursor_position(pos)
        table.table_header.repaint()

    header_renderer.add_seek_listener(table, MyColumns.LIFESPAN.ordinal(), on_seek)

    root.geometry("1000x200")
    window_closed = tk.simpledialog.askinteger("Input", "Enter a number")

    def on_window_close() -> None:
        root.destroy()
        return

    root.protocol('WM_DELETE_WINDOW', lambda: on_window_close())
    root.mainloop()

if __name__ == "__main__":
    test_demo_range_cell_renderer()
