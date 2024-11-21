from tkinter import *
import math

class ByteViewerOptionsDialog:
    def __init__(self, provider):
        self.provider = provider
        self.root = Toplevel()
        self.root.title("Byte Viewer Options")
        self.panel = Frame(self.root)
        self.panel.pack(fill=BOTH, expand=1)

        self.build_settings_panel()

        self.ok_button = Button(self.root, text="OK", command=self.ok_callback)
        self.cancel_button = Button(self.root, text="Cancel", command=self.root.destroy)
        self.ok_button.pack(side=LEFT)
        self.cancel_button.pack(side=RIGHT)

    def build_settings_panel(self):
        panel = Frame(self.panel)
        panel.pack(fill=BOTH, expand=1)

        label = Label(panel, text="Alignment Address:")
        label.pack()
        self.address_input_field = Entry(panel)
        self.address_input_field.insert(0, str(self.provider.get_alignment_address()))
        self.address_input_field.pack()

        bytes_per_line_label = Label(panel, text="Bytes Per Line:")
        bytes_per_line_label.pack()
        self.bytes_per_line_field = Spinbox(panel, from_=1, to=256, width=5)
        self.bytes_per_line_field.set(self.provider.get_bytes_per_line())
        self.bytes_per_line_field.pack()

        group_size_label = Label(panel, text="Group size (Hex View Only):")
        group_size_label.pack()
        self.group_size_field = Spinbox(panel, from_=1, to=256, width=5)
        self.group_size_field.set(self.provider.get_group_size())
        self.group_size_field.pack()

    def ok_callback(self):
        alignment_address = int(self.address_input_field.get(), 16)
        bytes_per_line = int(self.bytes_per_line_field.get())
        group_size = int(self.group_size_field.get())

        block_selection = self.provider.get_block_selection()
        offset = (alignment_address % bytes_per_line) if bytes_per_line else 0

        # Set the provider's properties
        self.provider.set_bytes_per_line(bytes_per_line)
        self.provider.set_group_size(group_size)
        self.provider.set_block_offset(offset)

        for view_name in list(self.provider.get_current_views()):
            checkbox = self.checkbox_map[view_name]
            if not checkbox.instate()[0]:
                self.provider.remove_view(view_name, True)

        # Add new views
        for view_name in self.checkbox_map:
            checkbox = self.checkbox_map[view_name]
            if checkbox.instate()[0] and view_name not in self.provider.get_current_views():
                self.provider.add_view(view_name)

        self.root.destroy()

    def build_view_options_panel(self):
        panel = Frame(self.panel)
        panel.pack(fill=BOTH, expand=1)

        outer_border = Frame(panel, borderwidth=5, relief=RIDGE)
        inner_border = Frame(outer_border, borderwidth=3, relief=GROOVE)
        outer_border.pack(side=TOP)
        inner_border.pack()

        data_model_names = self.provider.get_data_format_names()
        for format_name in data_model_names:
            checkbox = Checkbutton(inner_border, text=format_name)
            if format_name in self.provider.get_current_views():
                checkbox.select()
            else:
                checkbox.deselect()
            self.checkbox_map[format_name] = checkbox
            checkbox.pack(side=LEFT)

    def update(self):
        self.set_ok_enabled()

    def set_ok_enabled(self):
        # Check for valid field values here

    def at_least_one_view_on(self):
        return any(checkbox.instate()[0] for checkbox in self.checkbox_map.values())

# Usage:
provider = ByteViewerComponentProvider()  # Replace with your provider
dialog = ByteViewerOptionsDialog(provider)
