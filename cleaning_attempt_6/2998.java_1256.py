import tkinter as tk
from tkinter import filedialog
from tkinter.messagebox import showinfo, showerror

class CreateEmptyProgramScript:
    def __init__(self):
        self.dialog = NewLanguageDialog()

    def run(self):
        try:
            SwingUtilities.invokeAndWait(lambda: state.get_tool().show_dialog(self.dialog))
            
            pair = self.dialog.selected_language_compiler_spec_pair
            if pair is None:
                print("User cancelled operation.")
            else:
                language, compiler_spec = pair
                
                program = ProgramDB("Untitled", language, compiler_spec, self)
                
                program_manager = state.get_tool().get_service(ProgramManager)
                program_manager.open_program(program)
                
                program.release(self)
        except Exception as e:
            showerror("Error Creating New Program", str(e))

class NewLanguageDialog(tk.Toplevel):
    def __init__(self, parent=None):
        super().__init__()
        
        self.panel = tk.Frame(self)
        self.is_ok = False
        
        panel = tk.Frame(parent or self)
        panel.pack(fill="both")
        
        new_language_panel = tk.Frame(panel)
        new_language_panel.pack()
        
        # Add widgets to the panel
        for widget in ["language", "compiler"]:
            label = tk.Label(new_language_panel, text=widget.capitalize())
            entry = tk.Entry(new_language_panel)
            
            label.grid(row=len(entry), column=0)
            entry.grid(row=len(entry), column=1)

    def ok_callback(self):
        if self.panel.get_selected_lcs_pair() is None:
            self.set_status_text("Please select a language.")
            return
        self.is_ok = True
        self.destroy()

    def close(self):
        super().destroy()
        self.panel.dispose()

    def cancel_callback(self):
        self.is_ok = False
        self.destroy()

    @property
    def selected_language_compiler_spec_pair(self):
        if not self.is_ok:
            return None
        return self.panel.get_selected_lcs_pair()


class ProgramDB:
    pass

class ProgramManager:
    pass


state = {"get_tool": lambda: "Tool", "get_service": lambda x: "Service"}
