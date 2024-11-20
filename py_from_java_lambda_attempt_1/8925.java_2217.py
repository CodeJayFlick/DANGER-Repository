Here is the translation of the Java code to Python:
```
import abc

class AddressEditorPanel:
    def __init__(self):
        pass

    def __init__(self, double_buffered=False):
        self.double_buffered = double_buffered
        # Assuming a GUI framework like Tkinter or PyQt,
        # you would create the panel here using their respective APIs.

    def set_layout(self, layout=None, double_buffered=False):
        if layout:
            self.layout = layout

    @abc.abstractmethod
    def get_address(self) -> 'Address':
        raise NotImplementedError("Must be implemented by subclass")

    @abc.abstractmethod
    def set_address_panel_listener(self, listener: callable):
        pass


class AddressEditorPanelListener(ABC):
    # This is the interface for the address panel listener.
    pass

# Assuming you want to use Tkinter as your GUI framework,
# here's an example of how you could create a subclass:
import tkinter as tk
from . import Address  # assuming this class exists elsewhere in your codebase

class MyAddressEditorPanel(AddressEditorPanel):
    def __init__(self, parent: tk.Tk):
        super().__init__()
        self.parent = parent
        self.panel = tk.Frame(parent)
        self.panel.pack()

    def get_address(self) -> Address:
        # implement this method to return the current address value
        pass

    def set_address_panel_listener(self, listener: callable):
        # implement this method to notify the listener of changes
        pass
```
Note that I've used Python's `abc` module for abstract methods and classes. This is not strictly necessary in Python 3.x, but it helps enforce interface compliance.

I also assumed you would use a GUI framework like Tkinter or PyQt to create your panel. If you're using something else, the initialization code will be different.