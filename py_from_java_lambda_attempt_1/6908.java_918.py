Here is the translation of the given Java code into Python:

```Python
import os
from tkinter import filedialog
from tkinter.messagebox import showerror, askyesno

class ExportToCAction:
    EXPORT_ICON = "images/page_edit.png"
    LAST_USED_C_FILE = "last.used.decompiler.c.export.file"

    def __init__(self):
        super().__init__("Export to C")
        self.set_help_location(HelpTopics.DECOMPILER, "ToolBarExport")
        self.set_tool_bar_data(new ToolBarData(self.EXPORT_ICON, "Local"))
        self.setDescription("Export the current function to C")

    def read_last_used_file(self):
        filename = Preferences.get_property(self.LAST_USED_C_FILE)
        if not filename:
            return None
        return os.path.join(os.getcwd(), filename)

    def save_last_used_file(self, file_path):
        Preferences.set_property(self.LAST_USED_C_FILE, file_path)
        Preferences.store()

    def get_file(self, decompiler_panel):
        last_used_file = self.read_last_used_file()
        
        extensions = ["h", "c", "cpp"]
        root = tk.Tk()
        root.withdraw()
        file_chooser = filedialog.asksaveasfilename(filetypes=[("C/ C++ Files", "*.h;*.c;*.cpp")])
        if last_used_file:
            file_chooser.set_path(last_used_file)
        
        selected_file = file_chooser.get_path()
        if not selected_file:
            return None
        
        self.save_last_used_file(selected_file)

        has_extension = False
        path = os.path.abspath(selected_file)
        for extension in extensions:
            if path.lower().endswith("." + extension):
                has_extension = True
                break

        if not has_extension:
            file_chooser.set_path(path + ".c")
        
        return selected_file

    def is_enabled_for_decompiler_context(self, context):
        return bool(context.get_function() and context.get_c_code_model())

    def decompiler_action_performed(self, context):
        file = self.get_file(context.get DecompilerPanel())
        if not file:
            return
        
        if os.path.exists(file):
            if askyesno("Overwrite Existing File?", "Do you want to overwrite the existing file?"):
                return

        try:
            with open(file, 'w') as writer:
                grp = context.get_c_code_model()
                printer = PrettyPrinter(context.get_function(), grp)
                decomp_func = printer.print(True)
                writer.write(decomp_func.get_C())
            showinfo("Export to C", "Successfully exported function(s) to " + file)

        except Exception as e:
            showerror("Error Exporting to C", f"Error exporting to C: {e}")
```

Please note that Python does not have direct equivalent of Java's Swing and AWT libraries. The GUI components used in the code are from Tkinter, which is a built-in Python library for creating simple graphical user interfaces (GUIs).