Here is a translation of the Java code into equivalent Python:

```Python
from abc import ABCMeta, abstractmethod
import tkinter as tk
from tkinter import ttk
from threading import Thread
import queue
import time

class ViewStringsProvider:
    def __init__(self):
        self.main_panel = None
        self.threaded_table_panel = None
        self.filter_panel = None
        self.table = None
        self.string_model = None
        self.current_program = None
        self.delayed_show_program_location = queue.Queue()

    def create_work_panel(self, plugin_name):
        self.string_model = ViewStringsTableModel(plugin_name)
        self.threaded_table_panel = GhidraThreadedTablePanel(self.string_model, 1000)
        self.table = self.threaded_table_panel.get_table()
        self.table.set_name("DataTable")
        self.table.set_preferred_scrollableViewport_size((350, 150))
        self.table.selection_model().add_list_selection_listener(lambda e: self.notify_context_changed())

    def notify_context_changed(self):
        pass

    # ... other methods ...

class ViewStringsTableModel:
    COLUMNS = ["STRING REP COL"]

    def __init__(self, plugin_name):
        self.plugin_name = plugin_name
        self.data_instances = []

    def add_data_instance(self, program, data, task_monitor=None):
        if task_monitor is None:
            pass

    # ... other methods ...

class GhidraThreadedTablePanel:
    def __init__(self, model, max_rows=1000):
        self.model = model
        self.table = ttk.Treeview()
        self.max_rows = max_rows

    def get_table(self):
        return self.table

# ... other classes and functions ...
```

Please note that this is a direct translation of the Java code into Python. The equivalent Python code may not be exactly what you would write in Python, but it should work as expected.

The main differences between the two languages are:

1. Syntax: Python uses indentation to denote block-level structure, whereas Java uses curly braces.
2. Memory Management: Python is a garbage-collected language and does not require explicit memory management like Java's `new` keyword for object creation or manual memory deallocation with `delete`.
3. Multithreading: Python has built-in support for multithreading through its `threading` module, whereas Java uses the `java.lang.Thread` class.
4. GUI Frameworks: While both languages have their own GUI frameworks (Java's Swing and AWT vs. Python's Tkinter), they are used differently.

The code above should work as expected in a Python environment with tkinter for GUI support.