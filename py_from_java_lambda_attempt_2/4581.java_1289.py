Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import ttk
from typing import List

class AddressSetEditorPanel:
    def __init__(self, address_factory: 'AddressFactory', address_set_view: 'AddressSetView'):
        self.address_factory = address_factory
        self.address_set = new_address_set(address_set_view)
        
        self.min_address_field = tk.Entry()
        self.max_address_field = tk.Entry()

        self.add_range_button = ttk.Button(text='Add Range')
        self.remove_range_button = ttk.Button(text='Remove Selected Ranges')

        self.list_model = AddressSetListModel(self.address_set.to_list())
        self.list = tk.Listbox(list=self.list_model)

    def create_add_remove_panel(self):
        panel = tk.Frame()
        
        min_label = tk.Label(panel, text='Min:')
        max_label = tk.Label(panel, text='Max:')

        min_address_field_layout = tk.Frame(panel)
        min_address_field_layout.pack(side=tk.LEFT)
        self.min_address_field.pack_in_place(min_address_field_layout)

        max_address_field_layout = tk.Frame(panel)
        max_address_field_layout.pack(side=tk.LEFT)
        self.max_address_field.pack_in_place(max_address_field_layout)

        add_range_button_layout = tk.Frame(panel)
        add_range_button_layout.pack(side=tk.LEFT)
        self.add_range_button.pack_in_place(add_range_button_layout)

        remove_range_button_layout = tk.Frame(panel)
        remove_range_button_layout.pack(side=tk.LEFT)
        self.remove_range_button.pack_in_place(remove_range_button_layout)

        return panel

    def create_remove_panel(self):
        bottom_buttons = tk.Frame()
        
        self.remove_range_button = ttk.Button(bottom_buttons, text='Remove Selected Ranges')
        self.remove_range_button.pack()

        return bottom_buttons

    def create_list_panel(self):
        list_panel = tk.Frame()
        
        scrollpane = tk.Scrollbar(list_panel)
        self.list. pack(side=tk.LEFT, fill=tk.BOTH)
        scrollpane.pack(side=tk.RIGHT, fill=tk.Y)

        return list_panel

class AddressSetListModel:
    def __init__(self, address_list: List):
        self.address_list = address_list
        self.data = address_list

    def set_data(self, data: List):
        self.data = data
        self.fire_contents_changed(0, len(data))

    def get_element_at(self, index: int) -> 'AddressRange':
        return self.data[index]

    def get_size(self) -> int:
        return len(self.data)

class AddressSetView:
    pass

def new_address_set(address_set_view):
    # This is a placeholder for the actual implementation
    return address_set_view

# You would need to implement these classes in Python
class AddressFactory:
    pass

class AddressRange:
    pass
```

Please note that this translation does not include all the functionality of the original Java code. The `AddressSet`, `AddressInput`, and other related classes are missing, as they do not have direct equivalents in Python.