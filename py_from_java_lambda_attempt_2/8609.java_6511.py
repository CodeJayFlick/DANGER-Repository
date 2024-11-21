Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import filedialog

class ConfigPdbDialog:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Configure Symbol Server Search")
        self.symbol_server_config_panel = None
        self.was_success = False

    @property
    def wasSuccess(self):
        return self.was_success

    @wasSuccess.setter
    def wasSuccess(self, value):
        self.was_success = value

    def show_symbol_server_config(self):
        self.build()
        self.root.mainloop()

    def build(self):
        self.symbol_server_config_panel = SymbolServerPanel(self.on_symbol_server_service_change)
        self.add_buttons()
        self.add_work_panel(self.symbol_server_config_panel)

    def on_symbol_server_service_change(self, new_service):
        if new_service is not None:
            self.ok_button.config(state='normal')
        else:
            self.ok_button.config(state='disabled')

    def add_buttons(self):
        self.ok_button = tk.Button(self.root, text="OK", command=self.ok_callback)
        self.cancel_button = tk.Button(self.root, text="Cancel", command=self.cancel_callback)

    def ok_callback(self):
        if self.symbol_server_config_panel.is_config_changed():
            self.symbol_server_config_panel.save_config()
        self.was_success = True
        self.close()

    def cancel_callback(self):
        self.close()

    def close(self):
        self.root.destroy()

class SymbolServerPanel:
    def __init__(self, on_symbol_server_service_change):
        self.on_symbol_server_service_change = on_symbol_server_service_change

    def push_add_location_button(self):
        # implement this method
        pass

    def set_symbol_servers(self, symbol_servers):
        # implement this method
        pass

    def is_config_changed(self):
        return True  # implement this method to check if config has changed

    def save_config(self):
        # implement this method to save the config
        pass

class DockingWindowManager:
    @staticmethod
    def show_dialog(dialog):
        dialog.show_symbol_server_config()

if __name__ == "__main__":
    ConfigPdbDialog().show_symbol_server_config()
```

Note that some methods in the Java code are not implemented here, as they seem to be specific to a GUI framework (DockingWindowManager) and may require additional setup or libraries.