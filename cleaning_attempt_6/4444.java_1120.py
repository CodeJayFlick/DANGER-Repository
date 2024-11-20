import tkinter as tk
from tkinter import ttk
from typing import List

class PropertyManagerProvider:
    def __init__(self, plugin):
        self.plugin = plugin
        self.current_program = None
        self.restricted_view = None
        self.table = None
        self.model = None
        self.work_panel = None
        self.delete_action = None
        self.selection_listener = None
        self.table_model_listener = None

    def dispose(self):
        if self.plugin:
            self.plugin.remove_component_provider(self)

    def refresh(self):
        selection_model = self.table.selection()
        selection_model.disconnect(self.selection_listener)
        self.model.disconnect(self.table_model_listener)
        self.current_program = self.plugin.get_current_program()
        self.restricted_view = self.plugin.get_current_selection()

        selected_row = self.table.curselection()[0]
        if selected_row >= 0:
            prop_name = self.model.get_value_at(selected_row, PropertyManagerTableModel.PROPERTY_NAME_COLUMN)
            self.table.clear_selection()
        else:
            prop_name = None

        self.model.update(self.current_program, self.restricted_view)

        if prop_name is not None:
            rows = self.model.rowcount
            for i in range(rows):
                if prop_name == self.model.get_value_at(i, PropertyManagerTableModel.PROPERTY_NAME_COLUMN):
                    self.table.selection_set(i, i)
                    break

        self.model.add_table_model_listener(self.table_model_listener)
        selection_model.connect(self.selection_listener)

    def create_work_panel(self) -> tk.Frame:
        panel = tk.Frame()
        self.model = PropertyManagerTableModel()
        self.table_model_listener = lambda e: self.refresh_markers()
        self.model.add_table_model_listener(self.table_model_listener)

        self.table = ttk.Treeview(self, columns=PropertyManagerTableModel.PROPERTY_NAME_COLUMN)
        self.table.heading(PropertyManagerTableModel.PROPERTY_NAME_COLUMN, text="Name")
        self.table.column(PropertyManagerTableModel.PROPERTY_NAME_COLUMN, width=200)
        self.selection_listener = lambda e: self.refresh_markers()
        self.table.bind('<<TreeviewSelect>>', self.selection_listener)

        table_scrollpane = tk.Scrollbar(self, orient=tk.VERTICAL, command=self.table.yview)
        self.table.configure(yscrollcommand=table_scrollpane.set)

        panel.pack(side='top')

    def refresh_markers(self):
        pass

    def get_component(self) -> tk.Frame:
        if not self.work_panel:
            self.work_panel = self.create_work_panel()
            self.refresh()

        return self.work_panel
