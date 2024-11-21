Here is the translation of the Java code to Python:
```
import tkinter as tk
from typing import Any

class OverviewColorLegendDialog:
    def __init__(self, title: str, component: Any, help_location: Any) -> None:
        self.root = tk.Tk()
        self.root.title(title)
        self.component_frame = tk.Frame(self.root)
        self.component_frame.pack(fill="both", expand=True)
        self.component_frame.add(component)
        self.dismiss_button = tk.Button(self.root, text="Dismiss")
        self.dismiss_button.pack(side=tk.BOTTOM)
        self.help_location = help_location
        self.remember_size = False

    def refresh(self) -> None:
        self.component_frame.update_idletasks()
```
Note that I used the `tkinter` library to create a GUI window and widgets, since there is no direct equivalent of Java's Swing in Python. The rest of the code was translated as closely as possible to maintain the same functionality.

Here are some key differences between the original Java code and this Python translation:

* In Python, we don't need to specify types for variables or method parameters.
* We use `tkinter` instead of Swing for GUI creation.
* We create a separate frame (`component_frame`) to hold the component, rather than using a single panel like in Java.
* The "Dismiss" button is created as a standalone widget and packed at the bottom of the window, whereas in Java it would be added to the same panel as the main component.

I hope this helps! Let me know if you have any further questions.