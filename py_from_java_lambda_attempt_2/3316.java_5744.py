Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import ttk
import html.escape

class ConflictInfoPanel:
    def __init__(self):
        self.conflict_type = None
        self.conflict_num = 0
        self.total_conflicts = 0
        self.min_address = None
        self.max_address = None
        self.address_num = 0
        self.total_addresses = 0
        self.is_code_unit = False
        self.west_label = tk.Label()
        self.east_label = tk.Label()

    def create(self):
        self.root = tk.Tk()
        self.frame = ttk.Frame(self.root)
        self.frame.pack(fill='both', expand=True)

        self.west_label.grid(row=0, column=0, sticky='nsew')
        self.east_label.grid(row=1, column=1, sticky='nsew')

    def get_conflict_type(self):
        return self.conflict_type

    def get_address(self):
        return self.min_address

    def set_conflict_type(self, conflict_type):
        self.conflict_type = conflict_type
        self.west_label.config(text=self.get_register_text())

    def set_conflict_info(self, conflict_num, total_conflicts):
        self.conflict_num = conflict_num
        self.total_conflicts = total_conflicts
        self.update_west()

    def set_register_info(self, register_name):
        self.register_name = register_name
        self.west_label.config(text=self.get_register_text())

    def get_register_text(self):
        return f"Register: {self.register_name}"

    def set_address_info(self, address, address_num, total_addresses):
        self.is_code_unit = False
        self.min_address = address
        self.max_address = address
        self.address_num = address_num
        self.total_addresses = total_addresses
        self.update_east()

    def update_west(self):
        text = f"Conflict #{self.conflict_num} of {self.total_conflicts}"
        if self.is_code_unit:
            text += f" for address range: {html.escape(str(self.min_address))}-{html.escape(str(self.max_address))}"
        else:
            text += f" @ address: {html.escape(str(self.min_address))}"
        self.west_label.config(text=text)

    def update_east(self):
        if self.is_code_unit:
            text = f"Address range #{self.address_num} of {self.total_addresses} with conflicts"
        else:
            text = f"Address #{self.address_num} of {self.total_addresses} with conflicts"
        self.east_label.config(text=text)

    def run(self):
        self.create()
        self.root.mainloop()

if __name__ == "__main__":
    panel = ConflictInfoPanel()
    panel.set_conflict_type("Symbols")
    panel.set_register_info("RAX")
    panel.set_address_info(0x100, 1, 10)
    panel.run()
```

Please note that Python does not have direct equivalent of Java's Swing library. Tkinter is a built-in Python library for creating GUIs and it was used in this translation to create the labels and frame.