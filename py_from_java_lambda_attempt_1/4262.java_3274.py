Here is the translation of the Java code to Python:
```
import tkinter as tk

class SearchFormat:
    def __init__(self, name: str, change_listener):
        self.name = name
        self.change_listener = change_listener
        self.is_big_endian = False  # equivalent to protected boolean isBigEndian in Java

    @property
    def name(self) -> str:
        return self._name

    def get_options_panel(self) -> tk.Frame:
        no_options_panel = tk.Frame()
        no_options_panel.borderwidth = 5
        no_options_panel.title("Format Options")
        return no_options_panel

    def set_endieness(self, is_big_endian: bool):
        self.is_big_endian = is_big_endian

    @property
    def uses_endieness(self) -> bool:
        return True

    @property
    def supports_backwards_search(self) -> bool:
        return True

    def get_tooltip(self) -> str:
        # abstract method, implement in subclass
        pass

    def get_search_data(self, input: str) -> object:
        # abstract method, implement in subclass
        pass


# Example usage:
class MySearchFormat(SearchFormat):
    def __init__(self, name: str, change_listener):
        super().__init__(name, change_listener)

    @property
    def get_tooltip(self) -> str:
        return "My Search Format"

    def get_search_data(self, input: str) -> object:
        # implement your search data logic here
        pass

my_format = MySearchFormat("My Format", lambda x: print(x))
print(my_format.name)
```
Note that I used the `tkinter` library to create a GUI component (the options panel), and implemented the abstract methods in Python using the `@property` decorator.