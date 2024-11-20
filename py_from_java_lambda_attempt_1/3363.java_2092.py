Here is a translation of the Java code into equivalent Python:

```Python
import tkinter as tk
from tkinter import scrolledtext
from tkinter import filedialog
from tkinter import messagebox

class ViewInstructionDetailsAction:
    def __init__(self):
        self.listing_merge_panel_plugin = None
        self.HELP_LOCATION = "Repository", "CodeUnitsConflict"

    def set_listing_merge_panel_plugin(self, listing_merge_panel_plugin):
        self.listing_merge_panel_plugin = listing_merge_panel_plugin

    def get_help_location(self):
        return self.HELP_LOCATION

    def is_valid_context(self, context):
        if isinstance(context.get_source_object(), FieldPanel):
            return True
        else:
            return False

    def is_enabled_for_context(self, context):
        if isinstance(context.get_code_unit(), Instruction):
            return True
        else:
            return False

    def add_to_popup(self, context):
        return self.is_valid_context(context)

    def action_performed(self, context):
        location = context.get_location()
        program = location.get_program()
        listing_merge_panel = self.listing_merge_panel_plugin.get_provider().get_component()
        version = listing_merge_panel.get_version_name(program)
        address = location.get_address()
        cu = program.get_listing().get_code_unit_containing(address)
        detail_string = CodeUnitDetails.get_instruction_details(cu)
        title = f"{version} version's Instruction Details @ {address}"
        dialog = tk.Toplevel(root, title=title)

        text_area = scrolledtext.ScrolledText(dialog, width=70, height=20)
        font = "Monospaced", 12
        text_area.config(font=font)
        text_area.insert("1.0", detail_string)
        text_area.config(state="disabled")

        dialog.geometry("700x200")
        self.listing_merge_panel_plugin.get_tool().show_dialog(dialog, listing_merge_panel)

    def create_details_pane(self, details):
        font = "Monospaced", 12

        text_area = scrolledtext.ScrolledText(root, width=70, height=20)
        text_area.config(font=font)
        text_area.insert("1.0", details)
        text_area.config(state="disabled")

        return text_area


class Dialog:
    def __init__(self, title, work_panel):
        self.root = tk.Tk()
        self.root.title(title)

        frame = tk.Frame(self.root)
        frame.pack(fill=tk.BOTH, expand=1)

        label = tk.Label(frame, text=title)
        label.pack()

        scrollable_frame = tk.Frame(frame)
        scrollable_frame.pack(fill=tk.BOTH, expand=1)

        work_panel.grid(row=0, column=0, sticky="nsew")

    def show(self):
        self.root.mainloop()


root = tk.Tk()
action = ViewInstructionDetailsAction()
```

Please note that this is a translation of the Java code into Python. It may not be exactly equivalent in terms of functionality or performance due to differences between languages and libraries used.