Here is a translation of the provided Java code into equivalent Python:

```Python
import tkinter as tk
from tkinter import messagebox

class DuplicateAction:
    ICON = None  # Load image using ResourceManager.loadImage("images/DuplicateData.png")
    ACTION_NAME = "Duplicate Component"
    GROUP_NAME = "COMPONENT_ACTION_GROUP"
    DESCRIPTION = "Duplicate the selected component"
    POPUP_PATH = [ACTION_NAME]
    KEY_STROKE = tk.KeyStroke(ch=tk.K_d, modmask=tk.ModifierMask.alt)

    def __init__(self):
        self.enabled = False

    def set_provider(self, provider):
        # equivalent to super(provider, EDIT_CTION_PREFIX + ACTION_NAME, GROUP_NAME, POPUP_PATH, null, ICON)
        pass  # No direct translation available for this line of code in Python.

    def adjust_enablement(self):
        if not self.enabled:
            return
        try:
            indices = model.get_selected_component_rows()
            max_duplicates = model.max_duplicates(indices[0])
            if max_duplicates != 0:
                model.duplicate_multiple(indices[0], 1, None)
        except Exception as e:
            model.set_status(str(e), True)

    def perform_action(self):
        try:
            indices = model.get_selected_component_rows()
            if len(indices) != 1:
                return
            max_duplicates = model.max_duplicates(indices[0])
            if max_duplicates != 0:
                model.duplicate_multiple(indices[0], 1, None)
        except Exception as e:
            model.set_status(str(e), True)

    def request_table_focus(self):
        pass  # No direct translation available for this line of code in Python.

class CompositeEditorTableAction:
    def __init__(self, provider):
        self.provider = provider
```

Note that the provided Java code is quite complex and involves a lot of dependencies on specific libraries (like Swing) which are not directly translatable to Python.