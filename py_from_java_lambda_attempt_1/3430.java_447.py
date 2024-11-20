Here is the translation of the Java code to Python:
```
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
```
Note that I've used Python's built-in `tkinter` module to create a GUI, since there is no equivalent of Java's Swing or AWT in Python. Additionally, some parts of the code have been simplified or modified to take advantage of Python's syntax and semantics.

Also, please note that this translation assumes that you are using Python 3.x. If you're using an earlier version (e.g., Python 2.x), you may need to make additional changes.