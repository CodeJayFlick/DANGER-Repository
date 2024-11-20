import tkinter as tk
from typing import Any

class UpdateAlignmentAction:
    def __init__(self, plugin: Any, model: Any, alignment: int) -> None:
        self.plugin = plugin
        self.alignment = alignment
        self.model = model
        
        menu_path = ["Alignment", str(alignment)]
        # Note: In Python, we don't need to create a separate MenuData class like in Java.
        # We can simply use the `menu` attribute of the Tkinter widget and set its text.
        self.menu = tk.Menu(self.plugin.get_menu(), tearoff=0)
        for path in menu_path:
            self.menu.add_cascade(label=path, underline=0)

    def dispose(self) -> None:
        # Note: In Python, we don't need to remove the alignment listener explicitly like in Java.
        # The garbage collector will take care of it when the object is no longer referenced.
        pass

    def actionPerformed(self, context: Any) -> None:
        current_alignment = self.model.get_alignment()
        if current_alignment != self.alignment:
            self.model.set_alignment(self.alignment)

    def alignment_changed(self) -> None:
        selected = self.model.get_alignment() == self.alignment
        # Note: In Python, we don't need to set the "selected" attribute explicitly like in Java.
        # We can simply use the `config` method of the Tkinter widget and set its value.
        self.config(selected)

    def alignment_permission_changed(self) -> None:
        selected = self.model.get_alignment() == self.alignment
        self.config(selected)
