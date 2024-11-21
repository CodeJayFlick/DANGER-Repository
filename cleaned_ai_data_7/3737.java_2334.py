import tkinter as tk
from tkinter import ttk

class SizeAlignmentPanel:
    def __init__(self):
        self.root = tk.Tk()
        self.treeview = ttk.Treeview(self.root)
        self.data_organization = None
        self.create_treeview()

    def create_treeview(self):
        for column in range(2):
            self.treeview.column(column, width=100)
            self.treeview.heading(column, text=["Size", "Alignment"][column])

        self.treeview.pack()
        self.root.mainloop()

    def set_organization(self, data_organization):
        if not isinstance(data_organization, dict):
            raise ValueError("Data organization must be a dictionary")
        self.data_organization = data_organization
        for row in range(len(list(self.data_organization.keys())) + 1):
            values = [str(size) for size in list(self.data_organization.keys())[:row]] + [""] * (2 - len(values))
            self.treeview.insert("", "end", values=values)

    def update_treeview(self, data_organization=None):
        if not isinstance(data_organization, dict):
            raise ValueError("Data organization must be a dictionary")
        for row in range(len(list(self.data_organization.keys())) + 1):
            size = list(self.data_organization.keys())[row - 1] if row > 0 else None
            values = [str(size)] + [""] * (2 - len(values))
            self.treeview.insert("", "end", values=values)

    def set_status_message(self, message):
        print(message)
