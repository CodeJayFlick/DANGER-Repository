Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import scrolledtext
from typing import List

class DiffDetailsProvider:
    DIFF_DETAILS_HIDDEN_ACTION = "Diff Details Hidden"
    AUTO_UPDATE_CHECK_BOX = "Auto Update Check Box"
    FILTER_DIFFS_CHECK_BOX = "Filter Diffs Check Box"
    DIFF_DETAILS_TEXT_AREA = "Diff Details Text Area"
    DIFF_DETAILS_PANEL = "Diff Location Details Panel"

    def __init__(self, plugin):
        self.plugin = plugin
        self.text_area = scrolledtext.ScrolledText()
        self.doc = tk.Text(self.text_area)
        self.filter_diffs_checkbox = tk.BooleanVar(value=False)
        self.auto_update_checkbox = tk.BooleanVar(value=True)

    def set_auto_update(self, selected: bool) -> None:
        self.auto_update_checkbox.set(selected)

    def set_filter_diffs(self, selected: bool) -> None:
        self.filter_diffs_checkbox.set(selected)

    def add_actions(self) -> None:
        refresh_details_action = tk.Button(text="Refresh Diff Details", command=lambda: self.refresh_details())
        refresh_details_action.pack()

    def create_auto_update_checkbox(self) -> None:
        auto_update_checkbox_frame = tk.Frame()
        auto_update_checkbox_label = tk.Label(auto_update_checkbox_frame, text="Automatically Update Details")
        auto_update_checkbox_checkbox = tk.Checkbutton(auto_update_checkbox_frame, variable=self.auto_update_checkbox)
        auto_update_checkbox_frame.pack()

    def create_filter_diffs_checkbox(self) -> None:
        filter_diffs_checkbox_frame = tk.Frame()
        filter_diffs_checkbox_label = tk.Label(filter_diffs_checkbox_frame, text="Only Show Expected Difference Types")
        filter_diffs_checkbox_checkbox = tk.Checkbutton(filter_diffs_checkbox_frame, variable=self.filter_diffs_checkbox)
        filter_diffs_checkbox_frame.pack()

    def location_changed(self) -> None:
        if self.is_displayed and self.auto_update:
            self.refresh_details()

    def refresh_details(self) -> None:
        # Your code here
        pass

    def set_document_to_error_message(self, message: str) -> None:
        try:
            self.doc.delete(1.0, tk.END)
            self.doc.insert(tk.END, message)
        except Exception as e:
            print(f"Unexpected exception: {e}")

    def get_diff_details(self, p1_address: int) -> None:
        # Your code here
        pass

    def create_diff_details_panel(self) -> tk.Frame:
        panel = tk.Frame()
        scrolled_text_area = scrolledtext.ScrolledText(panel)
        self.doc.pack(side=tk.LEFT)

        auto_update_checkbox_frame = tk.Frame()
        filter_diffs_checkbox_frame = tk.Frame()

        bottom_panel = tk.Frame()
        bottom_panel.pack(fill="x")

        return panel

    def get_component(self) -> tk.Frame:
        return self.create_diff_details_panel()

    def close_component(self) -> None:
        # Your code here
        pass

    is_displayed: bool = False
    p1_details_location: int = 0

def main():
    root = tk.Tk()
    plugin = Plugin()  # You need to implement this class
    provider = DiffDetailsProvider(plugin)
    panel = provider.get_component()

    for child in panel.winfo_children():
        if isinstance(child, tk.Frame):
            child.pack(fill="both", expand=True)

    def on_close():
        root.destroy()
        plugin.close_component()  # You need to implement this method

    button = tk.Button(root, text="Close", command=on_close)
    button.pack()

    root.mainloop()

if __name__ == "__main__":
    main()
```

Please note that you will have to replace the `Plugin` class and its methods with your own implementation.