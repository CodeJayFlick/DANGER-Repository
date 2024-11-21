Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import ttk
from PIL import ImageTk, Image

class NameConflictsPanel:
    def __init__(self, listener):
        self.listener = listener
        self.panel = tk.Frame()
        self.create()

    def create(self):
        panel = tk.Frame(self.panel)
        panel.pack(side=tk.TOP)

        icon_panel = tk.Frame(panel)
        icon_panel.pack(side=tk.LEFT)

        conflicts_label = tk.Label(icon_panel, text="'My' name already exists in Latest Version")
        image_icon = ImageTk.PhotoImage(Image.open("images/information.png"))
        label_icon = tk.Label(icon_panel, image=image_icon)
        label_icon.image = image_icon
        icon_panel.pack(side=tk.TOP)

        keep_other_rb = ttk.Radiobutton(panel, text="Keep 'Other' Name", variable=None)
        add_or_rename_rb = ttk.Radiobutton(panel, text="Rename 'My' name to My.username")
        original_rb = ttk.Radiobutton(panel, text="Use 'Original' name")

        group = tk.StringVar()
        keep_other_rb.config(variable=group)
        add_or_rename_rb.config(variable=group)
        original_rb.config(variable=group)

    def set_names(self, result_program, latest_name, my_name, orig_name, name_change_only):
        conflicts_label['text'] = f"Tree named '{latest_name}' ({MergeConstants.LATEST_TITLE}) " \
                                   f"conflicts with '{my_name}' ({MergeConstants.MY_TITLE})"
        
        text = ""
        if name_change_only:
            text += f"Use name '{latest_name}' ({MergeConstants.LATEST_ITLE}) "
        else:
            text += f"Use '{latest_name}' ({MergeConstants.LATEST_ITLE}) & lose '{my_name}' ({MergeConstants.MY_TITLE})"
        
        keep_other_rb['text'] = text

        my_text = ""
        if my_name == latest_name:
            my_text += f"Add '{my_name}' ({MergeConstants.MY_TITLE}) as '{ProgramTreeMergeManager.get_unique_tree_name(result_program, my_name)}'"
        else:
            my_text += f"Add tree '{my_name}' ({MergeConstants.MY_TITLE})"
        
        add_or_rename_rb['text'] = my_text

        orig_text = ""
        if name_change_only:
            orig_text += f"Use original name '{orig_name}' ({MergeConstants.ORIGINAL_ITLE}) "
        else:
            if orig_name == latest_name:
                orig_text += f"Restore '{orig_name}' ({MergeConstants.ORIGINAL_TITLE}) as '{ProgramTreeMergeManager.get_unique_tree_name(result_program, orig_name)}' & lose '{my_name}' ({MergeConstants.MY_TITLE})"
            else:
                orig_text += f"Restore '{orig_name}' ({MergeConstants.ORIGINAL_ITLE}) & lose '{my_name}' ({MergeConstants.MY_TITLE})"
        
        original_rb['text'] = orig_text

    def get_selected_option(self):
        if keep_other_rb.get():
            return ProgramTreeMergeManager.KEEP_OTHER_NAME
        elif add_or_rename_rb.get():
            return ProgramTreeMergeManager.RENAME_PRIVATE
        elif original_rb.get():
            return ProgramTreeMergeManager.ORIGINAL_NAME
        else:
            return -1

    def set_selected(self, option):
        if option == ProgramTreeMergeManager.KEEP_OTHER_NAME:
            keep_other_rb.set()
        elif option == ProgramTreeMergeManager.RENAME_PRIVATE:
            add_or_rename_rb.set()
        elif option == ProgramTreeMergeManager.ORIGINAL_NAME:
            original_rb.set()

class MergeConstants:
    LATEST_TITLE = "Latest Version"
    MY_TITLE = "My Name"
    ORIGINAL_TITLE = "Original Name"

# Usage
listener = None  # You need to implement this class or method.
panel = NameConflictsPanel(listener)
```

Note: The `ImageTk` and `PIL` modules are used for image handling. Make sure you have these installed in your Python environment.

Also, the classes `ProgramTreeMergeManager`, `GRadioButton`, `GIconLabel`, etc., do not exist in Python's standard library or tkinter module. You need to implement them according to their functionality.