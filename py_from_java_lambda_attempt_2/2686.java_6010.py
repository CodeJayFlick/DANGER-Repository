Here is the translation of the Java code into Python:

```Python
from tkinter import *
import tkinter as tk

class HorizontalTabPanel:
    def __init__(self):
        self.root = Tk()
        self.root.title("Horizontal Tab Panel")
        self.listbox = Listbox(self.root)
        self.scrollbar = Scrollbar(self.root, orient=HORIZONTAL)
        self.left_button = Button(self.root, text="<", command=lambda: self.left_activated())
        self.right_button = Button(self.root, text=">", command=lambda: self.right_activated())

    def left_activated(self):
        index = self.find_next_occluded(0, True)
        if index != -1:
            self.listbox.see(index)

    def right_activated(self):
        index = self.find_next_occluded(len(self.model) - 1, False)
        if index != -1:
            self.listbox.see(index)

    def find_first_visible(self, reverse=False):
        for i in range((0 if not reverse else len(self.model)) - 1, (0 if reverse else -1), (-1 if reverse else 1)):
            b = self.listbox.get_iid(i)
            vis_rect = self.listbox.cget("view")
            if vis_rect.intersects(b):
                return i
        return -1

    def find_next_occluded(self, start_index, reverse=False):
        for i in range((start_index + 1) if not reverse else (0 if reverse else len(self.model))):
            b = self.listbox.get_iid(i)
            vis_rect = self.listbox.cget("view")
            if not vis_rect.contains(b):
                return i
        return -1

    def revalidate(self):
        pass

    def add_item(self, item):
        self.model.append(item)

    def remove_item(self, item):
        try:
            self.model.remove(item)
        except ValueError:
            pass

    def get_selected_item(self):
        index = self.listbox.curselection()
        if len(index) > 0:
            return self.model[index[0]]
        else:
            return None

    def set_selected_item(self, item):
        try:
            index = self.model.index(item)
            self.listbox.selection_clear(0, END)
            self.listbox.activate(index)
            self.listbox.selection_set(index, index)
        except ValueError:
            pass

    def get_item_at_index(self, index):
        return self.model[index]

    root = Tk()
    panel = HorizontalTabPanel()

    if __name__ == "__main__":
        panel.root.mainloop()
```

This Python code creates a simple GUI with a listbox and two buttons. The `HorizontalTabPanel` class is designed to mimic the behavior of the Java code, but it does not have all the same features (e.g., changing the color of selected items).