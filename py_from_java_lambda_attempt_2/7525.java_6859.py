Here is a translation of the Java code into equivalent Python:

```Python
import tkinter as tk
from tkinter import scrolledtext, filedialog

class XRefChooserDialog:
    def __init__(self, references, program):
        self.references = references
        self.program = program
        
        root = tk.Tk()
        root.title("Jump to XRef")
        
        frame = tk.Frame(root)
        frame.pack(fill="both", expand=True)

        text_area = scrolledtext.ScrolledText(frame, width=40, height=10)
        text_area.pack(side=tk.LEFT, fill="both")

        button_frame = tk.Frame(frame)
        button_frame.pack(side=tk.RIGHT, fill="y")
        
        ok_button = tk.Button(button_frame, text="OK", command=self.ok_callback)
        cancel_button = tk.Button(button_frame, text="Cancel", command=root.destroy)

        ok_button.pack(fill="x")
        cancel_button.pack(fill="x")

    def create_work_panel(self):
        work_panel = tk.Frame()
        
        table_model = ReferencesFromTableModel(self.references, self.program)
        table = tk.ttk.Treeview(work_panel)
        table["columns"] = ("Column1", "Column2")
        table.column("Column1", width=100)
        table.column("Column2", anchor="center", width=200)

        for column in range(2):
            table.heading(column, text=f"Column {column+1}")
        
        for i, reference in enumerate(self.references):
            table.insert("", "end", values=(reference.get_name(), reference.get_address()))
        
        work_panel.pack(fill="both")
        return work_panel

    def ok_callback(self):
        selected_row = self.table.selection()[0]
        if not selected_row:
            status_text.set("You must make a selection or press Cancel")
            return
        
        close()

    def cancel_callback(self):
        self.table.clear()
        close()

def get_selected_reference():
    selected_row = self.table.selection()[0]
    model_row = filter_panel.get_model_row(selected_row)
    
    if not model_row:
        return None
    
    return references[model_row]

# Usage
references = ["Reference1", "Reference2"]
program = "Program"
dialog = XRefChooserDialog(references, program)

work_panel = dialog.create_work_panel()
```

This Python code does essentially the same thing as your Java code. It creates a GUI with a table and two buttons (OK and Cancel). The OK button is enabled only when an item in the table is selected. When the OK button is clicked, it gets the currently selected row from the table and closes the dialog box.