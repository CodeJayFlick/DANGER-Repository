Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import messagebox

class SelectFromListDialog:
    def __init__(self, title, prompt, items):
        self.root = tk.Tk()
        self.root.title(title)
        self.items = list(items)

        frame = tk.Frame(self.root)
        frame.pack()

        label = tk.Label(frame, text=prompt + ":\n")
        label.pack(side=tk.TOP)

        self.listbox = tk.Listbox(frame)
        for item in items:
            self.listbox.insert(tk.END, str(item))
        self.listbox.selection_clear(0, tk.END)
        self.listbox.selection_set(0, 0)
        self.listbox.bind("<<ListboxSelect>>", lambda event: self.okCallback())
        self.listbox.pack(side=tk.LEFT)

    def okCallback(self):
        if len(self.items) > 0:
            messagebox.showinfo("Selection made", "You selected: " + str(self.get_selected_item()))
            self.root.destroy()

    def get_selected_item(self):
        return self.items[self.listbox.curselection()[0]]

def select_from_list(items, title="Select from list", prompt=""):
    dialog = SelectFromListDialog(title, prompt, items)
    dialog.root.mainloop()
    if len(dialog.items) > 0:
        return dialog.get_selected_item()
    else:
        return None

# Example usage
items = ["Item1", "Item2", "Item3"]
selected_item = select_from_list(items, title="Select an item")
print(selected_item)
```

This Python code does not use Java's Swing library or its equivalent in Python (tkinter). Instead, it uses tkinter for creating the GUI.