import tkinter as tk
from tkinter import filedialog, messagebox
from typing import List

class GraphExporterDialog:
    def __init__(self, graph: object, exporters: List[object]):
        self.graph = graph
        self.exporters = exporters
        self.last_used_exporter_name = "JSON"
        
        self.file_path_text_field = tk.StringVar()
        self.file_chooser_button = None
        
        self.combobox = None
        
    def build_work_panel(self) -> object:
        panel = tk.Frame(parent=self)
        panel.pack(fill=tk.X, padx=10, pady=5)
        return panel
    
    def build_main_panel(self) -> object:
        panel = tk.Frame(parent=self)
        panel.pack(fill=tk.X, padx=10, pady=5)
        
        label1 = tk.Label(panel, text="Format:")
        label2 = tk.Label(panel, text="Output File:")
        
        self.combobox = ttk.Combobox(panel, values=[exporter.__name__ for exporter in self.exporters])
        if not self.last_used_exporter_name:
            self.combobox.set(self.get_default_exporter().__name__)
        
        file_path_text_field = tk.Entry(parent=panel)
        file_chooser_button = tk.Button(parent=panel, text="Browse", command=self.choose_destination_file)
        
        label1.pack(side=tk.LEFT)
        self.combobox.pack(side=tk.LEFT)
        label2.pack(side=tk.LEFT)
        file_path_text_field.pack(side=tk.LEFT)
        file_chooser_button.pack(side=tk.LEFT)
        
        return panel
    
    def choose_destination_file(self):
        file = filedialog.asksaveasfilename()
        if not file:
            return
        
        self.file_path_text_field.set(file)
    
    def get_default_exporter(self) -> object:
        for exporter in self.exporters:
            if exporter.__name__ == self.last_used_exporter_name:
                return exporter
        return self.exporters[0]
    
    def validate(self):
        if not self.get_selected_exporter():
            messagebox.showerror("Error", "Please select an exporter format.")
            return
        
        file_to_export_into = self.file_path_text_field.get()
        if len(file_to_export_into) == 0:
            messagebox.showerror("Error", "Please enter a destination file.")
            return
        
        try:
            file = open(file_to_export_into, 'w')
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return
        finally:
            if not self.get_selected_exporter():
                messagebox.showerror("Error", "The specified output file is read-only.")
                return
        
    def get_selected_exporter(self) -> object:
        return self.combobox.get()
    
    def ok_callback(self):
        last_used_directory = os.path.dirname(self.file_path_text_field.get())
        
        if do_export():
            close()
        else:
            messagebox.showerror("Error", "Failed to export the graph.")
    
    def do_export(self) -> bool:
        success = False
        try:
            exporter = self.get_selected_exporter()
            file_to_export_into = os.path.join(last_used_directory, self.file_path_text_field.get())
            
            if not os.path.exists(file_to_export_into):
                with open(file_to_export_into, 'w') as f:
                    pass
            
            exporter.export_graph(self.graph, file_to_export_into)
        except Exception as e:
            messagebox.showerror("Error", str(e))
        
        return success
    
    def set_last_used_directory(self, directory: str) -> None:
        self.last_used_exporter_name = os.path.basename(directory)

if __name__ == "__main__":
    graph = object()  # replace with your actual graph
    exporters = [object(), object()]  # replace with your actual exporters
    
    dialog = GraphExporterDialog(graph, exporters)
    
    root = tk.Tk()
    root.title("Export Graph")
    
    panel = dialog.build_work_panel()
    panel.pack(fill=tk.X, padx=10, pady=5)
    
    ok_button = tk.Button(root, text="OK", command=dialog.ok_callback)
    cancel_button = tk.Button(root, text="Cancel", command=root.destroy)
    
    root.mainloop()

