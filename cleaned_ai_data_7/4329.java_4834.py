import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from threading import Thread
from queue import Queue

class StringTableProvider:
    def __init__(self):
        self.plugin = None
        self.options = None
        self.current_program = None
        self.make_strings_options_showing = True
        self.table = None
        self.string_model = None
        self.threaded_table_panel = None
        self.filter_panel = None

    def create_main_panel(self):
        panel = tk.Frame()
        panel.pack(fill='both', expand=True)
        return panel

    def build_make_string_options_panel(self):
        panel = tk.Frame()
        panel.pack(fill='x')
        offset_field = tk.Entry(panel, width=4)
        preview = tk.Text(panel, height=5)

        auto_label_checkbox = tk.Checkbutton(panel, text="Auto Label")
        add_alignment_bytes_checkbox = tk.Checkbutton(panel, text="Include Alignment Nulls")
        allow_truncation_checkbox = tk.Checkbutton(panel, text="Truncate If Needed")

        make_string_button = tk.Button(panel, text="Make String", command=lambda: self.make_string(False))
        make_char_array_button = tk.Button(panel, text="Make Char Array", command=lambda: self.make_string(True))

        panel.pack(fill='x')

    def build_table_panel(self):
        string_model = StringTableModel()
        threaded_table_panel = ttk.Treeview(string_model)
        table = threaded_table_panel

        filter_panel = ttk.Frame(threaded_table_panel)

        toggle_show_make_string_options_button = tk.Button(filter_panel, text="Toggle Make Strings Panel On/Off", command=self.toggle_show_make_string_options)

        panel = tk.Frame()
        panel.pack(fill='both', expand=True)
        return panel

    def make_string(self, is_array):
        # implement the logic here
        pass

    def toggle_show_make_string_options(self):
        self.make_strings_options_showing = not self.make_strings_options_showing
        if self.make_strings_options_showing:
            toggle_show_make_string_options_button.config(text="Toggle Make Strings Panel On/Off", image=EXPAND_ICON)
        else:
            toggle_show_make_string_options_button.config(text="Toggle Make Strings Panel On/Off", image COLLAPSE_ICON)

    def update_sub_title(self):
        # implement the logic here
        pass

class StringTableModel:
    def __init__(self, tool=None):
        self.tool = tool
        self.options = None
        self.data = []

    def get_row_object(self, row_index):
        return self.data[row_index]

    def set_program(self, program):
        # implement the logic here
        pass

class StringTable:
    def __init__(self, model):
        self.model = model
