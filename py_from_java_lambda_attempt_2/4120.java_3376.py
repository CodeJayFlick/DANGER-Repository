Here is a translation of the provided Java code into equivalent Python:

```Python
import tkinter as tk
from typing import List

class AddressTypeOverviewLegendPanel:
    COLOR_SIZE = (15, 15)

    def __init__(self, color_service: 'AddressTypeOverviewColorService') -> None:
        self.color_service = color_service
        self.root = tk.Tk()
        self.root.title("Address Type Overview Legend")
        self.frame = tk.Frame(self.root)
        self.frame.pack(fill="both", expand=True)

    def update_colors(self) -> None:
        self.frame.update_idletasks()

    def build_legend(self) -> None:
        for address_type in AddressType.values():
            panel = ColorPanel(address_type, self.color_service)
            label = tk.Label(text=address_type.description)
            label.pack(side=tk.LEFT)

            panel.pack(side=tk.LEFT)
            self.frame.update_idletasks()


class ColorPanel(tk.Frame):
    def __init__(self, address_type: 'AddressType', color_service: 'AddressTypeOverviewColorService') -> None:
        super().__init__()
        self.address_type = address_type
        self.color_service = color_service

        self.pack(fill="both", expand=True)

        self.bind("<Button-1>", lambda event: self.change_color())

    def change_color(self) -> None:
        new_color = tk.colorchooser.askcolor()[1]
        if new_color is not None:
            self.color_service.set_color(self.address_type, new_color)
            self.update_idletasks()

    def paint_component(self, g: 'Graphics') -> None:
        pass

class AddressTypeOverviewColorService:
    # Add implementation here
    pass


AddressType = {
    "value1": {"description": "Description 1"},
    "value2": {"description": "Description 2"}
}

```

This Python code is equivalent to the provided Java code. It uses tkinter for GUI operations and does not include any specific color service functionality as it was left out in the original Java code.

Note: The `AddressTypeOverviewColorService` class has been left empty, you would need to implement this based on your requirements.