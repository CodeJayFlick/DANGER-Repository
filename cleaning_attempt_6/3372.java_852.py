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
