Here is a translation of the Java code into equivalent Python code:

```Python
import tkinter as tk
from tkinter import messagebox

class ClearFlowDialog:
    def __init__(self, plugin):
        self.plugin = plugin
        self.panel = None
        self.symbols_cb = None
        self.data_cb = None
        self.repair_cb = None
        self.context = None

        super().__init__("Clear Flow")
        self.create()
        self.add_work_panel(self.panel)
        self.add_ok_button()
        self.add_cancel_button()
        help_location = HelpLocation(plugin.get_name(), "Clear_Flow_and_Repair")
        self.set_help_location(help_location)

    def ok_callback(self):
        self.close()

        if self.symbols_cb.get() and self.data_cb.get():
            self.plugin.clear_flow_and_repair(self.context, True, True)
        elif not self.symbols_cb.get() and not self.data_cb.get():
            self.plugin.clear_symbols()
        else:
            self.plugin.repair_flow()

    def cancel_callback(self):
        self.close()

    def create(self):
        listener = lambda event: None

        if event.keycode == 13:
            ok_callback()

        panel = tk.Frame(root)
        panel.pack(fill="both", expand=True)

        label = tk.Label(panel, text="Clear Flow Options:")
        label.pack(side=tk.TOP, fill="x")

        cb_panel = tk.Frame(panel)
        bl = tk.Pack(bl=0).pack()
        cb_panel.pack(fill="both", expand=True)

        self.symbols_cb = tk.BooleanVar(value=False)
        symbols_checkbox = tk.Checkbutton(cb_panel, text="Clear Symbols")
        data_checkbox = tk.Checkbutton(cb_panel, text="Clear Data")
        repair_checkbox = tk.Checkbutton(cb_panel, text="Repair Flow")

    def set_program_action_context(self, context):
        self.context = context

class HelpLocation:
    def __init__(self, name, help_text):
        self.name = name
        self.help_text = help_text

root = tk.Tk()
dialog = ClearFlowDialog(plugin)
```

Please note that Python's tkinter module is used for GUI operations.