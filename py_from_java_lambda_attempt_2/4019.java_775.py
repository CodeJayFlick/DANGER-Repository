Here is the translation of the Java code to Python:
```python
import tkinter as tk

class NavigationPanel(tk.Frame):
    def __init__(self, manager):
        super().__init__()
        self.manager = manager
        self.init()

    def init(self):
        # process mouse events
        self.bind("<Button-1>", lambda e: self.on_mouse_press(e))

    def on_mouse_press(self, event):
        if event.num == 1:
            self.manager.navigate_to(event.x, event.y)

    def paint_component(self, canvas):
        super().paint_component(canvas)
        self.manager.paint_navigation(canvas, self)

class MarkerManager:
    pass

# Example usage
manager = MarkerManager()
panel = NavigationPanel(manager)
```
Note that I used the `tkinter` library to create a GUI component in Python. The code is not identical to the original Java code, but it achieves similar functionality.

Here's what changed:

* In Java, you have separate classes for panels and markers. In Python, we combined them into one class (`NavigationPanel`) that inherits from `tk.Frame`.
* We replaced the `MouseListener` with a lambda function bound to the `<Button-1>` event (left mouse button click).
* The `paintComponent` method is now called `paint_component`, and it takes a `canvas` object instead of a `Graphics` object.
* I didn't implement the `MarkerManager` class, as it's not clear what its responsibilities are. You can add your own implementation or modify this code to fit your needs.

Keep in mind that Python is an interpreted language, so you might need to adjust the code to work with your specific use case and requirements.