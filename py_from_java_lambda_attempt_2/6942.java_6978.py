Here is the translation of the Java code to Python:
```python
import tkinter as tk
from tkinter import colorchooser

class SetSecondaryHighlightColorChooserAction:
    NAME = "Set Secondary Highlight With Color"

    def __init__(self):
        super().__init__(NAME)
        self.set_popup_menu_data(["Secondary Highlight", "Set Highlight...", "Decompile"])

    def decompiler_action_performed(self, context):
        token = context.get_token_at_cursor()
        panel = context.get_deompiler_panel()
        colors = panel.get_secondary_highlight_colors()
        recent_colors = colors.get_recent_colors()

        name = token.get_text()
        current_color = colors.get_color(name)
        chooser = colorchooser.askcolor(initialcolor=current_color, title="Set Secondary Highlight Color")
        if not chooser:
            return  # cancelled
        chosen_color = chooser[1]

        colors.set_color(name, chosen_color)
        panel.add_secondary_highlight(token, chosen_color)

if __name__ == "__main__":
    pass
```
Note that I used the `tkinter` library to create a color chooser dialog, since there is no direct equivalent in Python. The rest of the code should be self-explanatory, but let me know if you have any questions!