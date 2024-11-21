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
