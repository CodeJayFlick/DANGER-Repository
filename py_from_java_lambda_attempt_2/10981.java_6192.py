Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
import os

class AboutDomainObjectUtils:
    def __init__(self):
        self.COPY_MOUSE_LISTENER = PopupMouseListener()

    def displayInformation(self, tool, domain_file, metadata, title, additional_info, help_location):
        about_comp = self.get_about_panel(domain_file, metadata, additional_info)
        if about_comp is None:
            return
        dialog = Dialog(title=title, work_panel=about_comp)
        if help_location is not None:
            dialog.set_help_location(help_location)
        tool.show_dialog(dialog)

    def add_info(self, panel, name, value):
        if value is None:
            value = "?????"
        name_field = tk.Text(name, width=len(name), wrap=tk.WORD)
        name_field.insert('1.0', name + '\n')
        name_field.config(state='disabled')

        value_field = tk.Text(value, width=len(value), wrap=tk.WORD)
        value_field.insert('1.0', value + '\n')
        value_field.config(state='disabled')

        panel.pack(side=tk.LEFT)

    def get_about_panel(self, domain_file, metadata, additional_info):
        font = 'Monospaced'
        about_panel = tk.Frame()
        property_scroll = scrolledtext.ScrolledText(about_panel)
        content_panel = tk.Frame()

        self.add_info(content_panel, "Project File Name:", domain_file.name)

        last_modified = domain_file.last_modified_time
        if last_modified != 0:
            self.add_info(content_panel, "Last Modified:", str(last_modified))

        self.add_info(content_panel, "Readonly:", str(domain_file.read_only))

        for key in metadata.keys():
            value = metadata[key]
            self.add_info(content_panel, key + ":", value)

        if additional_info is not None and len(additional_info) > 0:
            aux_area = scrolledtext.ScrolledText(about_panel)
            aux_area.insert('1.0', additional_info)
            aux_area.config(state='disabled')
            sp = tk.Frame()
            sp.pack(side=tk.BOTTOM, fill=tk.X)

        info_panel = tk.Frame()

        panel = tk.Frame()
        panel.pack(fill=tk.BOTH, expand=1)

    def init(self):
        self.add_work_panel(work_panel)
        self.add_ok_button()
        set_remember_size(True)

    @staticmethod
    def ok_callback():
        close()

class PopupMouseListener:
    def process_popup_mouse_event(self, e):
        component = e.widget

        if isinstance(component, tk.Text) or isinstance(component, tk.Frame):
            return

        point = e.x_root, e.y_root
        within_bounds = component.winfo_ismapped() and 0 <= x < component.winfo_width() and 0 <= y < component.winfo_height()

        if e.num == 1:
            JPopupMenu popup_menu = new JPopupMenu()
            JMenuItem item = new JMenuItem("Copy")
            item.addActionListener(event -> write_data_to_clipboard(component))
            popup_menu.add(item)
            popup_menu.show(component, x, y)

    def write_data_to_clipboard(self):
        system_clipboard.set_contents(create_contents(), None)


class Dialog:
    def __init__(self, title, work_panel):
        super().__init__()
        self.init(work_panel)

    @staticmethod
    def init(work_panel):
        add_work_panel(work_panel)
        add_ok_button()
        set_remember_size(True)

    @staticmethod
    def ok_callback():
        close()

class StringTransferable:
    def __init__(self, data):
        super().__init__()
        self.data = data

    def get_data(self):
        return self.data


if __name__ == "__main__":
    about_domain_object_utils = AboutDomainObjectUtils()
```

Note: This is a direct translation of the Java code into Python. However, please note that this may not be optimal or idiomatic Python code.