import tkinter as tk
from tkinter import scrolledtext, messagebox

class DockingVisualVertex:
    def __init__(self, name):
        self.name = name
        self.text_area = scrolledtext.ScrolledText()
        self.generic_header = None
        self.max_width = 200

        self.text_area.insert('1.0', name)
        self.text_area.config(width=20, height=5)

    def set_max_width(self, width):
        self.max_width = width

class VisualVertex:
    pass

if __name__ == "__main__":
    # Create a Tkinter window
    root = tk.Tk()

    # Create an instance of DockingVisualVertex
    visual_vertex = DockingVisualVertex("Hello World")

    # Add the text area to the window
    visual_vertex.text_area.pack(fill='both', expand=True)

    # Start the Tkinter event loop
    root.mainloop()
