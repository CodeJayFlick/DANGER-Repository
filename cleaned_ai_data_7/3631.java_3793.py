import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

class RenameDataFieldDialog:
    def __init__(self):
        self.recent_choices = None
        self.choice_text_field = None
        
        self.component = None
        self.plugin = None
        self.program = None

    def set_data_component(self, program, component, name):
        self.component = component
        self.program = program
        self.choice_text_field.set_text(name)
        self.choice_text_field.select_all()

    def ok_callback(self):
        self.close()
        
        cmd = RenameDataFieldCmd(self.component, self.choice_text_field.get_text())
        self.plugin.execute(cmd, self.program)
        self.program = None

    def cancel_callback(self):
        self.program = None
        self.close()

    def create(self):
        recent_choices = tk.StringVar()
        choice_text_field = tk.Entry(textvariable=recent_choices)

        main_panel = tk.Frame()
        top_panel = tk.Frame(main_panel, borderwidth=5)
        
        top_panel.pack(side=tk.TOP, fill=tk.X)
        main_panel.pack(fill=tk.BOTH, expand=True)

        recent_choices.set("Enter new name")
        choice_text_field.insert(0, "Enter new name")

        def ok_callback():
            self.ok_callback()

        choice_text_field.bind("<Return>", lambda event: ok_callback())

        return main_panel

class RenameDataFieldCmd:
    def __init__(self, component, text):
        pass  # This class is not implemented in the original code.

# Usage
rename_data_field_dialog = RenameDataFieldDialog()
main_window = tk.Tk()
main_window.title("Rename Data Field")
main_window.geometry("300x100")

panel = rename_data_field_dialog.create()

main_window.mainloop()
