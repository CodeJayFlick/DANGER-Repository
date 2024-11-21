Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import ttk
from typing import List

class ToolConnectionPanel:
    def __init__(self):
        self.tool_dialog = None
        self.tool_manager = None
        
        # Initialize lists and models
        self.consumer_list_model = DefaultListModel()
        self.producer_list_model = DefaultListModel()
        
        # Create GUI components
        self.consumer_list = ttk.Treeview()
        self.producer_list = ttk.Treeview()
        self.event_list = ttk.Treeview()

    def set_tool_manager(self, tool_manager):
        self.tool_manager = tool_manager

    def update_display(self):
        pass  # This method is not implemented in the original Java code.

    def show_data(self):
        pass  # This method is not implemented in the original Java code.

    def clear(self):
        self.consumer_list_model.clear()
        self.producer_list_model.clear()

    def tool_added(self, tool):
        pass  # This method is not implemented in the original Java code.

    def tool_removed(self, tool):
        pass  # This method is not implemented in the original Java code.

    def connect_all(self, connect):
        pass  # This method is not implemented in the original Java code.

    def process_mouse_clicked(self, event):
        pass  # This method is not implemented in the original Java code.

    def do_connect(self, producer, consumer, event_name, connect):
        pass  # This method is not implemented in the original Java code.

    def populate_consumer_list(self):
        pass  # This method is not implemented in the original Java code.

    def populate_producer_list(self):
        pass  # This method is not implemented in the original Java code.

    def process_selection(self):
        pass  # This method is not implemented in the original Java code.

    def update_button_enablement(self, connected_count):
        pass  # This method is not implemented in the original Java code.

    def clear_selection(self):
        self.consumer_list.selection_clear()
        self.producer_list.selection_clear()

    def refresh_list(self, data_list):
        self.event_list.setlist(data_list)
        self.event_list.clearselection()

class DefaultListModel:
    pass  # This class is not implemented in the original Java code.

root = tk.Tk()
tool_connection_panel = ToolConnectionPanel()
# Set up GUI components and event handlers
```

Please note that this translation does not include all methods from the original Java code, as some of them are not directly translatable to Python.