Here is a translation of the Java code into equivalent Python code:

```Python
import tkinter as tk
from tkinter import messagebox

class HelloWorldComponentProvider:
    def __init__(self):
        self.main_panel = None
        self.active_button_obj = None
        self.action = None

    def build_main_panel(self):
        self.main_panel = tk.Frame()
        self.main_panel.pack(fill='both', expand=True)
        panel = tk.Frame(self.main_panel, borderwidth=20)
        panel.pack(side=tk.TOP, fill='x')
        active_button_obj = MyButton("Hello World")
        font = active_button_obj.cget('font')
        active_button_obj.config(font=('Helvetica', 14, 'bold'))
        panel.pack_slaves()[0].pack_slaves().append(active_button_obj)

    def create_actions(self):
        self.action = tk.Button(self.main_panel, text="Hello World", command=lambda: announce("Hello World"))
        self.action.pack(fill='x')

class MyButton(tk.Button):
    def __init__(self, name):
        super().__init__(name)
        self.config(borderwidth=10, relief=tk.RAISED)

root = tk.Tk()
component_provider = HelloWorldComponentProvider()
component_provider.build_main_panel()

def announce(message):
    messagebox.showinfo("Hello World", message)

root.mainloop()
```

This Python code does not exactly replicate the Java code. It is a simplified version that creates a GUI with buttons and displays messages using `messagebox`.