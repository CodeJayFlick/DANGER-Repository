Here is the translation of the Java code to Python:
```
import tkinter as tk

class MarkerPanel(tk.Frame):
    def __init__(self, master, manager):
        super().__init__(master)
        self.manager = manager
        ToolTipManager.register_component(self)

    def paint_component(self, g):
        super().paint_component(g)
        self.manager.paint_markers(g)

    def get_tooltip_text(self, event):
        return self.manager.get_tooltip(event)


class MarkerManager:
    pass  # implement the methods called by MarkerPanel


# Example usage
root = tk.Tk()
manager = MarkerManager()  # create an instance of MarkerManager
panel = MarkerPanel(root, manager)
panel.pack(side=tk.LEFT)  # place the panel to the left hand side

root.mainloop()
```
Note that I used `tkinter` (the Python equivalent of Java's Swing library) for creating GUI components. The rest of the code is translated from Java to Python using standard syntax and semantics.

Please note that this translation assumes a basic understanding of both Java and Python, as well as their respective libraries and frameworks. If you have any specific questions or need further clarification on certain parts of the code, feel free to ask!