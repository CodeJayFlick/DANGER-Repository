Here is the translation of the Java code to Python:
```
import tkinter as tk

class PageUpMenuKeyHandler:
    def process(self, manager, path):
        popup = self.get_leaf_popup(path)
        if popup is None:
            return
        active_index = self.find_active_menu_item_raw_index(manager, path)
        separator_index = -1
        if active_index >= 0:
            # Only search for separator with an active item. This will trigger the search to start at the bottom of the menu
            separator_index = self.find_previous_separator_index(popup, active_index - 1)
        next_index = self.find_previous_valid_index(popup, separator_index - 1)
        if next_index < 0:
            # wrap the search; start at the bottom
            separator_index = popup.get_component_count()
            next_index = self.find_previous_valid_index(popup, separator_index - 1)
        self.set_new_menu_item_index(manager, path, next_index)

    def get_leaf_popup(self, path):
        pass

    def find_active_menu_item_raw_index(self, manager, path):
        pass

    def find_previous_separator_index(self, popup, index):
        pass

    def find_previous_valid_index(self, popup, index):
        pass

    def set_new_menu_item_index(self, manager, path, index):
        pass
```
Note that I've kept the method signatures and variable names similar to the original Java code, but you'll need to implement the `get_leaf_popup`, `find_active_menu_item_raw_index`, `find_previous_separator_index`, `find_previous_valid_index`, and `set_new_menu_item_index` methods in Python.