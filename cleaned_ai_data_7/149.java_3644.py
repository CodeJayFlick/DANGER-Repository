import tkinter as tk
from typing import List, Map, Any

class DebuggerAttachDialog:
    def __init__(self, provider):
        self.provider = provider
        self.plugin = provider.get_plugin()

        self.create_widgets()
        self.create_actions()

    def create_widgets(self):
        panel = tk.Frame()
        process_table = tk.ttk.Treeview(panel)
        process_table.heading("#0", text="Attachables")
        process_table.column("#0", width=200)

        filter_panel = tk.Frame(panel, bg='gray')
        panel.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        filter_panel.pack(fill=tk.X)

        self.processes = []
        for i in range(10):
            self.processes.append({
                'name': f'Process {i}',
                'id': str(i),
            })

        process_table.insert('', tk.END, values=self.processes)
        panel.update_idletasks()

    def create_actions(self):
        pass

    def attach(self):
        selected_row = int(process_table.selection()[0].split('#')[1])
        proc = self.processes[selected_row]
        if not proc:
            return
        print(f"Attaching to {proc['name']}")

class TargetAttachable:
    def __init__(self, name: str, id: str):
        self.name = name
        self.id = id

if __name__ == "__main__":
    provider = None  # Replace with your actual provider object
    dialog = DebuggerAttachDialog(provider)
