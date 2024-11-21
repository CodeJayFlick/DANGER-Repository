Here is the translation of the Java code to Python:
```python
import tkinter as tk

class FcgTooltipProvider:
    def get_tooltip(self, vertex):
        tip = tk.Toplevel()
        label = tk.Label(tip, text=vertex.name)
        label.pack()
        return tip

    def get_tooltip(self, vertex, edge=None):
        return None  # No tooltip for edges in this implementation

    def get_tooltip_text(self, vertex, event):
        child = event.widget
        if isinstance(child, tk.Button):  # Check if the widget is a button
            return child.tooltip_text()  # Return the button's tooltip text
        else:
            return str(vertex.name)  # Default to returning just the vertex name

# Example usage:
vertex = {"name": "My Function"}
tooltip_provider = FcgTooltipProvider()
tip = tooltip_provider.get_tooltip(vertex)
```
Note that I used the `tkinter` library (which is Python's equivalent of Java's Swing/AWT libraries) for creating GUI components, and implemented the methods as instance methods on a class.