from tkinter import *
import functools

class IconButtonTableCellEditor:
    def __init__(self, filter_panel, icon, action):
        self.filter_panel = filter_panel
        self.action = action
        self.button = Button()
        self.button.config(image=icon)
        self.button.pack()

    def get_cell_editor_value(self):
        return ""

    def get_table_cell_editor_component(self, table, value, selected, row, column):
        self.row = self.filter_panel.get_row_object(row)
        self.button.config(text=str(value))
        return self.button

    def action_performed(self, event):
        self.stop_editing()
        self.action.accept(self.row)

class GTableFilterPanel:
    def __init__(self):
        pass

    def get_row_object(self, row):
        # This method should be implemented based on your actual data structure
        return None

def main():
    root = Tk()

    filter_panel = GTableFilterPanel()
    icon = PhotoImage(file="icon.png")  # Replace with your own image file
    action = functools.partial(print, "Action performed!")  # Replace with your own action function

    editor = IconButtonTableCellEditor(filter_panel, icon, action)

    root.mainloop()

if __name__ == "__main__":
    main()
