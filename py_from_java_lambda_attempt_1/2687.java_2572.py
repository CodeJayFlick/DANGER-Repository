Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from typing import List

class GAddressRangeField:
    def __init__(self):
        self.factory = None
        self.root = tk.Tk()
        self.create_widgets()

    def create_widgets(self):
        frame = tk.Frame(self.root)
        frame.pack(side=tk.LEFT)

        self.space_label = tk.Label(frame, text="[")
        self.space_label.pack(side=tk.LEFT)

        self.field_space = tk.StringVar(value='0')
        self.space_combo = tk.OptionMenu(frame, self.field_space, *[])
        self.space_combo.set('0')

        self.space_combo.pack(side=tk.LEFT)

        self.min_label = tk.Label(frame, text=":")
        self.min_label.pack(side=tk.LEFT)

        self.field_min = tk.Entry(frame)
        self.field_min.insert(0, '0')
        self.field_min.pack(side=tk.LEFT)

        self.max_label = tk.Label(frame, text=", ")
        self.max_label.pack(side=tk.LEFT)

        self.field_max = tk.Entry(frame)
        self.field_max.insert(0, '0')
        self.field_max.pack(side=tk.LEFT)

        self.close_bracket = tk.Label(frame, text="]")
        self.close_bracket.pack(side=tk.LEFT)

    def set_address_factory(self, factory):
        if not isinstance(factory, dict):
            raise TypeError("AddressFactory must be a dictionary")
        for space_name in list(factory.keys()):
            self.space_combo['menu'].add_command(label=space_name, command=lambda s=space_name: self.field_space.set(s))
        self.factory = factory
        self.revalidate_min()
        self.revalidate_max()
        self.adjust_max_to_min()

    def get_space(self):
        if not isinstance(self.factory, dict) or not self.field_space.get():
            return None
        space_name = self.field_space.get()
        for name in list(self.factory.keys()):
            if name == space_name:
                return self.factory[name]
        raise ValueError("Invalid address space")

    def revalidate_min(self):
        if not isinstance(self.factory, dict) or not self.field_space.get():
            return
        space = self.get_space()
        min_address = long(int(space['min'], 16))
        max_address = long(int(space['max'], 16))

        try:
            address = int(self.field_min.get(), 16)
            if address < min_address:
                self.field_min.delete(0, tk.END)
                self.field_min.insert(0, hex(min_address)[2:])
            elif address > max_address:
                self.field_min.delete(0, tk.END)
                self.field_min.insert(0, hex(max_address)[2:])
        except ValueError:
            pass

    def revalidate_max(self):
        if not isinstance(self.factory, dict) or not self.field_space.get():
            return
        space = self.get_space()
        min_address = long(int(space['min'], 16))
        max_address = long(int(space['max'], 16))

        try:
            address = int(self.field_max.get(), 16)
            if address < min_address:
                self.field_max.delete(0, tk.END)
                self.field_max.insert(0, hex(min_address)[2:])
            elif address > max_address:
                self.field_max.delete(0, tk.END)
                self.field_max.insert(0, hex(max_address)[2:])
        except ValueError:
            pass

    def adjust_max_to_min(self):
        if not isinstance(self.factory, dict) or not self.field_space.get():
            return
        space = self.get_space()
        min_address = long(int(space['min'], 16))
        max_address = long(int(space['max'], 16))

        try:
            address = int(self.field_max.get(), 16)
            if address < min_address:
                self.field_max.delete(0, tk.END)
                self.field_max.insert(0, hex(min_address)[2:])
            elif address > max_address:
                self.field_max.delete(0, tk.END)
                self.field_max.insert(0, hex(max_address)[2:])
        except ValueError:
            pass

    def set_range(self, range):
        if not isinstance(range, dict) or 'space' not in range or 'min' not in range or 'max' not in range:
            raise TypeError("Range must be a dictionary with keys space, min and max")
        self.field_space.set(range['space'])
        try:
            address = int(self.field_min.get(), 16)
            if address < long(int(range['min'], 16)):
                self.field_min.delete(0, tk.END)
                self.field_min.insert(0, hex(long(int(range['min'], 16)))[2:])
            elif address > long(int(range['max'], 16)):
                self.field_min.delete(0, tk.END)
                self.field_min.insert(0, hex(long(int(range['max'], 16)))[2:])
        except ValueError:
            pass

    def get_range(self):
        if not isinstance(self.factory, dict) or not self.field_space.get():
            return None
        space_name = self.field_space.get()
        for name in list(self.factory.keys()):
            if name == space_name:
                break
        else:
            raise ValueError("Invalid address space")
        try:
            min_address = long(int(self.field_min.get(), 16))
            max_address = long(int(self.field_max.get(), 16))
            return {'space': space_name, 'min': hex(min_address)[2:], 'max': hex(max_address)[2:]}
        except ValueError:
            pass

    def set_enabled(self, enabled):
        self.root.config(state=tk.NORMAL if enabled else tk.DISABLED)
        for widget in [self.space_label, self.close_bracket]:
            widget.config(state=tk.NORMAL if enabled else tk.DISABLED)

if __name__ == "__main__":
    app = GAddressRangeField()
```

This Python code creates a simple GUI with three text fields and two combo boxes. The first combo box is used to select the address space, while the other two are for entering the minimum and maximum addresses in hexadecimal format.