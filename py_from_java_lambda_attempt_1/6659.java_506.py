Here is a translation of your Java code into equivalent Python:

```Python
import tkinter as tk
from tkinter import ttk
from threading import Thread
from queue import Queue

class PatternEvalTableProvider:
    def __init__(self, current_stats, parent, plugin, program):
        self.main_panel = tk.Frame(parent)
        super().__init__()
        self.set_transient()
        self.build_main_panel(plugin, program, current_stats)

    def build_main_panel(self, plugin, program, stats):
        pattern_panel = tk.Frame(self.main_panel)
        top_layout = ttk.Style().layout("Toplevel")
        pattern_panel.pack(side=tk.TOP, fill="both", expand=True)
        
        table_model = PatternEvalTableModel(plugin, program, stats.get_row_objects())
        threaded_table = GhidraThreadedTable(pattern_panel, table_model, 1000)

        go_to_service = plugin.get_tool().get_service(GoToService)
        if go_to_service is not None:
            threaded_table.install_navigation(go_to_service, go_to_service.get_default_navigatable())

        threaded_table.set_row_selection_allowed(True)
        threaded_table.set_selection_mode("multiple_interval")
        table_filter_panel = GhidraTableFilterPanel(threaded_table, table_model)

        pattern_panel.pack(side=tk.TOP, fill="both", expand=True)

    def build_info_panel(self, stats):
        eval_panel = tk.Frame()
        grid_layout = ttk.Style().layout("Toplevel")
        eval_panel.grid(column=0, row=0)
        
        for i in range(2):
            eval_panel.grid_columnconfigure(i, weight=1)
            eval_panel.grid_rowconfigure(i, weight=1)

    def get_component(self):
        return self.main_panel

class PatternEvalTableModel:
    pass  # Implement this class as needed.

class GhidraThreadedTable:
    pass  # Implement this class as needed.

class GhidraTableFilterPanel:
    pass  # Implement this class as needed.
```

This Python code is a direct translation of your Java code. However, please note that the `PatternEvalTableModel`, `GhidraThreadedTable`, and `GhidraTableFilterPanel` classes are not implemented in this code because they were missing from your original Java code. You will need to implement these classes according to their functionality.

Also, Python does not have direct equivalents of some Java features like anonymous inner classes or static imports. Therefore, the translation may look slightly different than what you would expect if you're familiar with both languages.