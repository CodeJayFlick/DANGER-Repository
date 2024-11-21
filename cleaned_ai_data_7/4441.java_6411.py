import tkinter as tk
from tkinter import filedialog, messagebox

class MemoryUsagePlugin:
    def __init__(self):
        self.dialog = None

    def setup_actions(self):
        action = tk.Button(text="Show VM memory", command=self.show_memory)
        action.pack()
        return action

    def show_memory(self):
        if not hasattr(self, 'dialog') or self.dialog is None:
            self.dialog = ShowMemoryDialog(self)
        else:
            self.dialog.focus_force()

class ShowMemoryDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__()
        # Your dialog code here
