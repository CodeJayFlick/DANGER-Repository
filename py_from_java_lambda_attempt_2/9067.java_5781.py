Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from PIL import ImageTk, Image

class MatchStatusRenderer:
    ACCEPTED_ICON = None
    REJECTED_ICON = None
    BLOCKED_ICON = None
    WARN_ICON = None
    FAILURE_ICON = None
    FULLY_APPLIED_ICON = None
    FULLY_CONSIDERED_ICON = None

    def __init__(self):
        self.ACCEPTED_ICON = ImageTk.PhotoImage(Image.open("images/flag.png"))
        self.REJECTED_ICON = ImageTk.PhotoImage(Image.open("images/dialog-cancel.png"))
        # self.REJECTED_ICON = ImageTk.PhotoImage(Image.open("images/delete.png"))  # commented out
        self.BLOCKED_ICON = ImageTk.PhotoImage(Image.open("images/kgpg.png"))

        self.WARN_ICON = ImageTk.PhotoImage(Image.open("images/bullet_error.png").resize((10,8)))
        self.FAILURE_ICON = ImageTk.PhotoImage(Image.open("images/edit-delete.png").resize((8,8)).transpose(Image.FLIP_LEFT_RIGHT).resize((10,8)))
        self.FULLY_APPLIED_ICON = ImageTk.PhotoImage(Image.open("images/checkmark_green.gif").resize((8,8)).transpose(Image.FLIP_LEFT_RIGHT).resize((10,8)))
        self.FULLY_CONSIDERED_ICON = ImageTk.PhotoImage(Image.open("images/checkmark_yellow.gif").resize((8,8)))

    def getTableCellRendererComponent(self, data):
        renderer = tk.Label()
        value = data.get()

        if not value:
            return renderer

        status = MungedAssocationAndMarkupItemStatus(value)

        icon = None
        if status == "ACCEPTED_FULLY_APPLIED":
            icon = self.ACCEPTED_ICON.subsample(1, 1)
        elif status == "ACCEPTED_HAS_ERRORS":
            icon = self.ACCEPTED_ICON.subsample(1, 1), self.FAILURE_ICON.subsample(1, 1)
        elif status == "ACCEPTED_NO_UNEXAMINED":
            icon = self.ACCEPTED_ICON.subsample(1, 1), self.FULLY_CONSIDERED_ICON.subsample(1, 1)
        elif status == "ACCEPTED_SOME_UNEXAMINED":
            icon = self.ACCEPTED_ICON.subsample(1, 1), self.WARN_ICON.subsample(1, 1)
        elif status == "AVAILABLE":
            pass
        elif status == "BLOCKED":
            icon = self.BLOCKED_ICON.subsample(1, 1)
        elif status == "REJECTED":
            icon = self.REJECTED_ICON.subsample(1, 1)

        renderer.config(image=icon)
        renderer.config(text="")
        renderer.config(compound="left")
        renderer.config(justify=tk.CENTER)

        return renderer
```

Please note that the above Python code is not a direct translation of Java to Python. It's more like an interpretation of what the original Java code does, and it might need some adjustments based on your specific use case.

Also, this code assumes you have PIL (Python Imaging Library) installed in your environment. If not, you can install it using pip:

```
pip install pillow
```