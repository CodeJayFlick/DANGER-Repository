Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from tkinter import messagebox
import threading

class FidSearchResultFrame:
    def __init__(self, title, func_list, service):
        self.service = service
        self.func_list = func_list
        self.model = None
        self.table = None
        self.root = tk.Tk()
        self.root.title(title)
        
        # Create the table model and view
        self.model = ttk.Treeview(self.root)
        self.model["columns"] = ("Name", "Hash", "Size")
        for column in self.model["columns"]:
            self.model.column(column, anchor="w", width=100)
        self.table = scrolledtext.ScrolledText(self.root)

    def build_frame(self):
        # Create the table
        self.model.pack()
        
        # Add data to the model
        for func_rec in self.func_list:
            item = self.model.insert("", "end")
            self.model.item(item, values=(func_rec.name, func_rec.hash, str(func_rec.size)))

    def build_menu_actions(self):
        menu_bar = tk.Menu(self.root)
        
        # Create edit menu
        edit_menu = tk.Menu(menu_bar, tearoff=0)
        for item in ["Set auto-fail", "Set auto-pass", "Set force-specific", "Set force-relation"]:
            action = lambda x=item: self.set_action(x)
            edit_menu.add_command(label=item, command=action)

        # Create clear menu
        clear_menu = tk.Menu(menu_bar, tearoff=0)
        for item in ["Clear auto-fail", "Clear auto-pass", "Clear force-specific", "Clear force-relation"]:
            action = lambda x=item: self.clear_action(x)
            clear_menu.add_command(label=item, command=action)

        # Create save menu
        save_menu = tk.Menu(menu_bar, tearoff=0)
        for item in ["Save changes"]:
            action = lambda x=item: self.save_changes()
            save_menu.add_command(label=item, command=action)

        # Add menus to the menu bar
        menu_bar.add_cascade(label="Edit", menu=edit_menu)
        menu_bar.add_cascade(label="Clear", menu=clear_menu)
        menu_bar.add_cascade(label="Save", menu=save_menu)

    def set_action(self, action):
        if self.func_list:
            try:
                # Call the service method
                self.service.mark_records_auto_fail(self.func_list, True)
                self.model.reset()
            except Exception as e:
                messagebox.showerror("Error performing " + action, str(e))

    def clear_action(self, action):
        if self.func_list:
            try:
                # Call the service method
                self.service.mark_records_force_relation(self.func_list, False)
                self.model.reset()
            except Exception as e:
                messagebox.showerror("Error performing " + action, str(e))

    def save_changes(self):
        if self.func_list:
            dedup_map = set()
            for func_rec in self.func_list:
                fid_db = func_rec.get_fid_db()
                if fid_db in dedup_map:
                    continue
                try:
                    # Call the service method
                    fid_db.save_database("saving", None)
                except Exception as e:
                    messagebox.showerror("Error performing 'Save changes'", str(e))

    def run(self):
        self.build_frame()
        self.root.mainloop()

# Create an instance of FidSearchResultFrame and start it
if __name__ == "__main__":
    func_list = ["Function 1", "Function 2"]
    service = None
    frame = FidSearchResultFrame("FID Search Result Frame", func_list, service)
    frame.run()
```

This Python code creates a GUI with a table view and several menu options. The `build_frame` method sets up the table model and view, while the `build_menu_actions` method adds items to the menus. The `set_action`, `clear_action`, and `save_changes` methods handle the actions performed by the user through the menus.

Please note that this is a translation of Java code into Python, so it may not be perfect or idiomatic Python.