import tkinter as tk
from PIL import ImageTk, Image

class LabelTestVertex:
    def __init__(self, name):
        self.name = name
        self.label = tk.Label(text=name)
        self.label.config(width=50, height=50, bg='yellow', borderwidth=1, relief="ridge", anchor=tk.CENTER)

    def get_component(self):
        return self.label

# Example usage:
test_vertex = LabelTestVertex("Hello World")
