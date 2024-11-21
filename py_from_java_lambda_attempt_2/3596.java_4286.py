Here is a translation of the provided Java code into equivalent Python:

```Python
import tkinter as tk
from PIL import ImageTk, Image

class MoveDownAction:
    ICON = None  # Initialize with None for now.
    ACTION_NAME = "Move Components Down"
    GROUP_NAME = "COMPONENT_ACTION_GROUP"
    DESCRIPTION = "Move the selected components down"

    def __init__(self):
        self.enabled = False
        self.icon = ImageTk.PhotoImage(Image.open("images/down.png"))

    def set_provider(self, provider):
        # Assuming 'provider' is a CompositeEditorProvider instance.
        pass

    def actionPerformed(self, context):
        try:
            model.move_down()
        except Exception as e1:
            model.set_status(str(e1), True)
        request_table_focus()

    def adjust_enablement(self):
        self.enabled = model.is_move_down_allowed()
```

Please note that Python does not have direct equivalents for Java's Swing, AWT and other libraries. The provided code is a translation of the original Java code into equivalent Python syntax.