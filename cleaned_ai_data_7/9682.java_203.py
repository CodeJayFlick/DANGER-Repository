import tkinter as tk
from tkinter import messagebox
from tkinter import simpledialog
from tkinter import filedialog
from tkinter import scrolledtext
from tkinter import ttk

class ListPanel:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("List Panel")
        
        # Create a frame to hold the list panel components.
        self.frame = tk.Frame(self.root)
        self.frame.pack(fill="both", expand=True)

        # Create a scrollable text area for displaying the list items.
        self.listbox = tk.Listbox(self.frame, width=30)
        self.scrollbar = tk.Scrollbar(self.frame)
        self.listbox.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.listbox.yview)

        # Pack the components
        self.listbox.pack(side="left", fill="both")
        self.scrollbar.pack(side="right", fill="y")

    def set_list_data(self, data):
        for item in data:
            self.listbox.insert("end", item)
            
    def get_selected_value(self):
        try:
            return self.listbox.get(self.listbox.curselection())
        except tk.TclError:
            return None

    def ensure_index_is_visible(self, index):
        if not self.listbox.index("end") > 0:
            self.listbox.see(index)
