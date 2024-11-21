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
