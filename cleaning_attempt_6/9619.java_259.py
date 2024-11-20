import tkinter as tk
from ghidra.util.filechooser import GhidraFileChooserModel

class FileTableCellRenderer:
    def __init__(self, chooser):
        self.model = chooser.get_model()
        self.chooser = chooser

    def get_table_cell_renderer_component(self, data):
        file = data['value']
        data['cell_data'] = (self.chooser.get_display_name(file), 
                             data['column_view_index'], 
                             data['selected'], 
                             data['has_focus'])
        c = super().get_table_cell_renderer_component(data)

        if isinstance(c, tk.Label):
            c.config(image=self.model.get_icon(file))
        return c
