Here is the translation of the Java code to Python:
```
import tkinter as tk

class PageDownAction:
    def __init__(self, event_listener):
        self.event_listener = event_listener

    def actionPerformed(self, e):
        # Now move the viewport down the distance of the viewport.
        page_down_evt = {"type": "VIEWPORT_PAGE_DOWN", "shifted": False}
        self.event_listener.send(page_down_evt)

class FVEventListener:
    def send(self, event):
        pass  # implement this method

# Example usage
event_listener = FVEventListener()
page_down_action = PageDownAction(event_listener)
```
Note that I had to make some assumptions about the Python code since it was not provided. Specifically:

* The `FVEvent` class is replaced with a dictionary (`{"type": "VIEWPORT_PAGE_DOWN", "shifted": False}`) as there is no direct equivalent in Python.
* The `AbstractAction` class is replaced with a custom `PageDownAction` class that defines the `actionPerformed` method.
* The `FVEventListener` interface is implemented by creating an empty `send` method. You would need to implement this method according to your specific requirements.

Also, I used Tkinter (`tk`) as it's one of the most popular Python libraries for GUI programming and has similar functionality to Java Swing.