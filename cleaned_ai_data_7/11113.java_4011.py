import tkinter as tk

class LogLevelTableCellRenderer:
    def __init__(self):
        self.trace_color = '#FFFFFF'
        self.debug_color = '#87B9EA'
        self.info_color = '#E0E0E0'
        self.warn_color = '#FFEC80'
        self.error_color = '#FF0000'
        self.fatal_color = '#8B0A1A'

    def get_cell_renderer_component(self, data):
        super().get_cell_renderer_component(data)
        
        value = str(data.get_value())
        
        if value.lower() == 'debug':
            return tk.Label(root, text=value, bg=self.debug_color, fg='black')
        elif value.lower() == 'trace':
            return tk.Label(root, text=value, bg=self.trace_color, fg='black')
        elif value.lower() == 'warn':
            return tk.Label(root, text=value, bg=self.warn_color, fg='black')
        elif value.lower() == 'info':
            return tk.Label(root, text=value, bg=self.info_color, fg='black')
        elif value.lower() == 'error' or value.lower() == 'fatal':
            return tk.Label(root, text=value, bg=self.error_color if value.lower() == 'error' else self.fatal_color, fg='black')

root = tk.Tk()
