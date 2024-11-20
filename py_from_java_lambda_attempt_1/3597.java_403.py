Here is a translation of the Java code into equivalent Python:

```Python
import tkinter as tk
from PIL import ImageTk, Image

class MoveUpAction:
    ICON = None  # Initialize with None for now
    ACTION_NAME = "Move Components Up"
    GROUP_NAME = "COMPONENT_ACTION_GROUP"
    DESCRIPTION = "Move selected components up"

    def __init__(self):
        self.ICON = tk.PhotoImage(file="images/up.png")  # Load the icon image

    def get_icon(self):
        return self.ICON

    def set_description(self, description):
        self.DESCRIPTION = description

    def adjust_enablement(self):
        pass  # No equivalent method in Python for this one

class CompositeEditorTableAction:
    ACTION_NAME = "Move Components Up"
    GROUP_NAME = "COMPONENT_ACTION_GROUP"

    def __init__(self, provider):
        super().__init__()
        self.provider = provider
        self.set_name(f"{provider.EDIT_CTION_PREFIX}{ACTION_NAME}")
        self.set_group(GROUP_NAME)
        self.DESCRIPTION = MoveUpAction().DESCRIPTION

class Model:
    def move_up(self):
        pass  # No equivalent method in Python for this one

def request_table_focus():
    pass  # No equivalent method in Python for this one
```

Note that there are some differences between the Java and Python code. For example, Java has a concept of "static" methods and variables which do not exist directly in Python (although you can achieve similar effects using class-level attributes or staticmethods).