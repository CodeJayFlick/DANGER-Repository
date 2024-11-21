import tkinter as tk
from tkinter import ttk
from typing import List

class DomainFilesPanel:
    def __init__(self, file_list: List[str], list_title: str):
        self.file_list = file_list
        self.checkboxes = []
        self.list_panel = None
        
        root = tk.Tk()
        frame = tk.Frame(root)
        frame.pack()

        for i in range(len(file_list)):
            checkbox = ttk.Checkbutton(frame, text=file_list[i], variable=tk.IntVar())
            checkbox.pack(side='left')
            self.checkboxes.append(checkbox)

        list_panel = tk.Listbox(frame)
        list_panel.pack(side='bottom')

    def get_selected_domain_files(self) -> List[str]:
        selected_files = []
        for i in range(len(self.file_list)):
            if self.checkboxes[i].instate(['selected']):
                selected_files.append(self.file_list[i])
        return selected_files

root = tk.Tk()
domain_files_panel = DomainFilesPanel(["File1", "File2"], "Domain Files")
root.mainloop()
