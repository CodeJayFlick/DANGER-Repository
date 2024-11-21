Here is the translation of the Java code to Python:
```
import tkinter as tk

class PageDownMenuKeyHandler:
    def process(self, manager, path):
        popup = self.get_leaf_popup(path)
        if popup is None:
            return

        active_index = self.find_active_menu_item_raw_index(manager, path)
        separator_index = self.find_next_separator_index(popup, active_index + 1)
        next_index = self.find_next_valid_index(popup, separator_index + 1)
        if next_index < 0:
            separator_index = -1  # wrap the search; start at the top
            next_index = self.find_next_valid_index(popup, separator_index + 1)

        self.set_new_menu_item_index(manager, path, next_index)

    def get_leaf_popup(self, path):
        pass  # implement this method

    def find_active_menu_item_raw_index(self, manager, path):
        pass  # implement this method

    def find_next_separator_index(self, popup, index):
        pass  # implement this method

    def find_next_valid_index(self, popup, index):
        pass  # implement this method

    def set_new_menu_item_index(self, manager, path, index):
        pass  # implement this method
```
Note that I had to remove the `@Override` annotation and some of the Java-specific syntax (e.g. `void process`, etc.) since Python does not have equivalent constructs. Additionally, I left out the implementation details for the methods marked as `pass`, which would need to be implemented in a real-world scenario.

Also, please note that this translation is just an approximation, and you may need to adjust it based on your specific requirements or use case.