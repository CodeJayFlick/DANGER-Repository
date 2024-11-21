import tkinter as tk
from tkinter import messagebox

class FidSearchDebugDialog:
    def __init__(self):
        self.service = None
        self.fid_query_service = None
        self.function_id_text_field = None
        self.name_text_field = None
        self.path_text_field = None
        self.full_hash_text_field = None
        self.specific_hash_text_field = None

    def set_function_id_text(self, id):
        if self.function_id_text_field:
            self.function_id_text_field.delete(0, tk.END)
            self.function_id_text_field.insert(0, id)

    def set_name_text(self, name):
        if self.name_text_field:
            self.name_text_field.delete(0, tk.END)
            self.name_text_field.insert(0, name)

    def set_domain_path_text(self, path):
        if self.path_text_field:
            self.path_text_field.delete(0, tk.END)
            self.path_text_field.insert(0, path)

    def set_full_hash_text(self, hash):
        if self.full_hash_text_field:
            self.full_hash_text_field.delete(0, tk.END)
            self.full_hash_text_field.insert(0, hash)

    def set_specific_hash_text(self, hash):
        if self.specific_hash_text_field:
            self.specific_hash_text_field.delete(0, tk.END)
            self.specific_hash_text_field.insert(0, hash)

    def build_panel(self):
        panel = tk.Frame()
        panel.pack(fill=tk.X)

        function_id_label = tk.Label(panel, text="Function ID:")
        function_id_label.pack(side=tk.LEFT)
        self.function_id_text_field = tk.Entry(panel, width=25)
        self.function_id_text_field.pack(side=tk.LEFT)

        name_label = tk.Label(panel, text="Name:")
        name_label.pack(side=tk.LEFT)
        self.name_text_field = tk.Entry(panel, width=25)
        self.name_text_field.pack(side=tk.LEFT)

        path_label = tk.Label(panel, text="Domain Path:")
        path_label.pack(side=tk.LEFT)
        self.path_text_field = tk.Entry(panel, width=25)
        self.path_text_field.pack(side=tk.LEFT)

        full_hash_label = tk.Label(panel, text="FH:")
        full_hash_label.pack(side=tk.LEFT)
        self.full_hash_text_field = tk.Entry(panel, width=25)
        self.full_hash_text_field.pack(side=tk.LEFT)

        specific_hash_label = tk.Label(panel, text="XH:")
        specific_hash_label.pack(side=tk.LEFT)
        self.specific_hash_text_field = tk.Entry(panel, width=25)
        self.specific_hash_text_field.pack(side=tk.LEFT)

    def close(self):
        if self.fid_query_service:
            try:
                self.fid_query_service.close()
            except Exception as e:
                messagebox.showerror("Error", str(e))
        super().close()

# Example usage
dialog = FidSearchDebugDialog()
panel = dialog.build_panel()
