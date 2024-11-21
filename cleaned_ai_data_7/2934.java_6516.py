import tkinter as tk
from tkinter import filedialog, messagebox
from typing import List

class SampleTableProvider:
    def __init__(self, plugin):
        self.plugin = plugin
        self.discovered_algorithms = find_algorithms()
        self.component = build_component()

    def dispose(self):
        self.filter_table.dispose()
        self.remove_from_tool()

    def build_component(self):
        panel = tk.Frame(parent=tk.Tk())
        panel.pack(fill='both', expand=True)

        table_panel, control_panel = self.build_panels()
        panel.grid(row=0, column=0)
        table_panel.grid(row=1, column=0)
        control_panel.grid(row=2, column=0)

    def build_panels(self):
        table_panel = tk.Frame(parent=tk.Tk())
        model = SampleTableModel(self.plugin)
        self.filter_table = GFilterTable(model)
        table_panel.pack(fill='both', expand=True)

        control_panel = tk.Frame(parent=tk.Tk())

        algorithms_panel, buttons_panel = self.build_control_panels()
        control_panel.grid(row=0, column=0)
        algorithms_panel.grid(row=1, column=0)
        buttons_panel.grid(row=2, column=0)

        return table_panel, control_panel

    def build_control_panels(self):
        algorithms_panel = tk.Frame(parent=tk.Tk())
        checkboxes = [GCheckBox(algorithm.name) for algorithm in self.discovered_algorithms]
        for i, checkbox in enumerate(checkboxes):
            panel.grid(row=i, column=0)

        buttons_panel = tk.Frame(parent=tk.Tk())

        run_button = tk.Button(text='Run Algorithms', command=lambda: model.reload())
        file_chooser_panel = GhidraFileChooserPanel('Output File')

    def find_algorithms(self):
        return [FunctionAlgorithm() for _ in range(len(discovered_algorithms))]

class GFilterTable:
    pass

class SampleTableModel:
    pass

class FunctionAlgorithm:
    pass
