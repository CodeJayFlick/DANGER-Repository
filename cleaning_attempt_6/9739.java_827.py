from tkinter import *
import tkinter as tk
from tkinter.ttk import *

class ColumnFilterPanel:
    def __init__(self, filter_entry):
        self.filter_entry = filter_entry
        self.panel = tk.Frame()
        self.panel.pack()

        self.build_constraint_panels()
        self.build_button_panel()

    def build_button_panel(self):
        panel = tk.Frame(self.panel)
        icon = PhotoImage(file="images/Plus.png")
        button = Button(panel, image=icon, command=lambda: self.filter_entry.add_filter_condition())
        button.pack(side=tk.TOP)

        panel.pack(side=tk.RIGHT)

    def build_constraint_panels(self):
        panel = tk.Frame(self.panel)
        panel.pack()

        column_combobox = Combobox()
        for item in self.filter_entry.get_all_column_data():
            column_combobox.insert(tk.END, str(item))
        column_combobox.current(0)
        column_combobox.bind("<<ComboboxSelected>>", lambda e: self.column_changed())

        panel.pack(side=tk.LEFT)

    def build_or_label(self):
        label = tk.Label(panel, text="<OR>", fg="gray")
        return label

    def column_changed(self, event=None):
        selected_index = int(column_combobox.current())
        selected_column_data = self.filter_entry.get_all_column_data()[selected_index]
        self.filter_entry.set_column_data(selected_column_data)

    def has_valid_filter_value(self):
        return self.filter_entry.has_valid_filter_value()

    def get_column_filter_entry(self):
        return self.filter_entry

class DialogFilterRow:
    pass
