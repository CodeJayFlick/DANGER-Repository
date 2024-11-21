Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import ttk

class NamePanel:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Resolve Tree Name Conflict")
        
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill="both", expand=True)

        self.keep_other_rb = tk.BooleanVar(value=False)
        self.keep_my_rb = tk.BooleanVar(value=False)
        self.new_tree_rb = tk.BooleanVar(value=False)
        self.original_rb = tk.BooleanVar(value=False)

        keep_other_button = ttk.Checkbutton(main_frame, text="Use name 'Other' Name", variable=self.keep_other_rb)
        keep_my_button = ttk.Checkbutton(main_frame, text="Use name 'My' Name", variable=self.keep_my_rb)
        new_tree_button = ttk.Checkbutton(main_frame, text="Add New Tree", variable=self.new_tree_rb)
        original_button = ttk.Checkbutton(main_frame, text="Use Original Name", variable=self.original_rb)

        keep_other_button.pack(fill="x")
        keep_my_button.pack(fill="x")
        new_tree_button.pack(fill="x")
        original_button.pack(fill="x")

    def set_names(self, name1, name2, orig_name):
        self.keep_other_rb.set(f"Use name '{name1}' ({MergeConstants.LATEST_TITLE})")
        self.keep_my_rb.set(f"Use name '{name2}' ({MergeConstants.MY_TITLE})")
        self.new_tree_rb.set(f"Add new tree named '{name2}'")
        self.original_rb.set(f"Use name '{orig_name}' ({MergeConstants.ORIGINAL_TITLE})")

    def get_selected_option(self):
        if self.keep_other_rb.get():
            return ProgramTreeMergeManager.KEEP_OTHER_NAME
        elif self.keep_my_rb.get():
            return ProgramTreeMergeManager.KEEP_PRIVATE_NAME
        elif self.new_tree_rb.get():
            return ProgramTreeMergeManager.ADD_NEW_TREE
        elif self.original_rb.get():
            return ProgramTreeMergeManager.ORIGINAL_NAME
        else:
            return ProgramTreeMergeManager.ASK_USER

    def create(self):
        panel = tk.Frame()
        panel.pack(fill="both", expand=True)

        rb_panel = tk.Frame(panel)
        rb_panel.pack(fill="x")

        self.root.mainloop()

class ProgramTreeMergeManager:
    KEEP_OTHER_NAME = 0
    KEEP_PRIVATE_NAME = 1
    ADD_NEW_TREE = 2
    ORIGINAL_NAME = 3
    ASK_USER = 4

if __name__ == "__main__":
    name_panel = NamePanel()
    name_panel.create()

```

Please note that Python does not have direct equivalent of Java's Swing library. Tkinter is a built-in Python library for creating GUIs, but it has different syntax and functionality than Swing.