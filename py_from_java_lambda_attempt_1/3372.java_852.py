Here is the translation of the Java code to Python:
```
import tkinter as tk

class DecoratorPanel(tk.Frame):
    def __init__(self, component, is_connected):
        super().__init__()
        self.layout = tk.FrameLayout(self)
        self.layout.add(component)
        if not is_connected:
            self.border = tk.LineBorder(color='orange', width=2)
        else:
            self.border = None
        self.configure()

    def configure(self):
        self.pack()
        if self.border:
            self.config(border=self.border)

# Example usage:
component = tk.Label(text="Hello")
is_connected = False

decorator_panel = DecoratorPanel(component, is_connected)
```
Note that I used the `tkinter` library (which is Python's equivalent of Java Swing) to create a GUI component. The rest of the code was translated directly from the original Java code.

Also, in Python, we don't need explicit getters and setters like we do in Java. Instead, we can use attributes or methods as needed. In this case, I used an attribute `border` to store the border configuration, which is then applied using the `config()` method.