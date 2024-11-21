import tkinter as tk

class GTableTextCellEditor:
    TABLE_FOCUSED_CELL_HIGHLIGHT_BORDER = "TABLE_FOCUSED_CELL_HIGHLIGHT_BORDER"

    def __init__(self, text_field):
        super().__init__()
        self.set_click_count_to_start(2)

        text_field.config(border=tk.get_border(TABLE_FOCUSED_CELL_HIGHLIGHT BORDER))

# Example usage:
text_field = tk.Text()
editor = GTableTextCellEditor(text_field)
