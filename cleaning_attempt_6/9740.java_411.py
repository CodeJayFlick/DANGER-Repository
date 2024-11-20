import tkinter as tk
from tkinter import ttk
from typing import Any, Dict, List

class ConstraintFilterPanel:
    def __init__(self, constraint_entry: Any, first_column_component: Any):
        self.constraint_entry = constraint_entry
        self.first_column_component = first_column_component
        
        self.root = tk.Tk()
        
        main_panel = ttk.Frame(self.root)
        main_panel.pack(fill=tk.BOTH, expand=True)

        detail_editor_panel = None

        if hasattr(constraint_entry.get_detail_editor_component(), '__call__'):
            detail_editor_panel = constraint_entry.get_detail_editor_component()

        if detail_editor_panel is not None:
            self.detail_editor_component = tk.Frame(self.root)
            self.detail_editor_component.pack(fill=tk.BOTH, expand=True)

        button_panel = ttk.Frame(self.root)
        button_panel.pack(side=tk.RIGHT, fill=tk.Y)

        delete_button = ttk.Button(button_panel, text="Delete", command=lambda: constraint_entry.delete())
        delete_button.pack()

    def build_main_panel(self) -> Any:
        panel = tk.Frame()
        
        if hasattr(self.first_column_component, '__call__'):
            self.first_column_component(panel)
        else:
            panel.create_window(0, 0, window=self.first_column_component)

        constraint_combo = ttk.Combobox(panel)
        constraint_combo.pack()

        inline_editor_panel = None

        if hasattr(constraint_entry.get_inline_editor_component(), '__call__'):
            inline_editor_panel = tk.Frame()
            inline_editor_panel.pack(fill=tk.BOTH, expand=True)

        return panel

    def build_detail_editor_panel(self) -> Any:
        self.detail_editor_component = constraint_entry.get_detail_editor_component()

        if self.detail_editor_component is None:
            return None
        
        detail_panel = tk.Frame()
        
        detail_panel.create_window(0, 0, window=self.detail_editor_component)

        return detail_panel

    def build_inline_editor_panel(self) -> Any:
        inline_editor_panel = tk.Frame()
        
        inline_editor_panel.create_window(0, 0, window=constraint_entry.get_inline_editor_component())

        return inline_editor_panel

    def build_constraint_combo(self) -> Any:
        panel = tk.Frame()

        constraint_combo = ttk.Combobox(panel)
        constraint_combo.pack()

        if hasattr(constraint_entry.get_column_constraints(), '__call__'):
            constraints = constraint_entry.get_column_constraints()
            for i in range(len(constraints)):
                constraint_combo.insert(i, constraints[i].get_name())

        return panel

    def build_button_panel(self) -> Any:
        button_panel = tk.Frame()

        delete_button = ttk.Button(button_panel, text="Delete", command=lambda: constraint_entry.delete())
        delete_button.pack(side=tk.LEFT)

        return button_panel

    def constraint_changed(self):
        selected_index = self.constraint_combo.current()
        if selected_index != -1:
            selected_constraint = constraint_entry.get_column_constraints()[selected_index]
            constraint_name = selected_constraint.get_name()
            constraint_entry.set_selected_constraint(constraint_name)
