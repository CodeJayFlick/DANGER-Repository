Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import filedialog, messagebox
from typing import List, Set

class AddressSetChoice:
    ENTIRE_PROGRAM = 0
    SELECTION = 1
    MANUALLY_DEFINED = 2


class ChooseAddressSetEditorPanel(tk.Frame):
    def __init__(self, master: tk.Tk, tool_name: str, program: Program, selection_address_set: List[Range], my_initial_address_set: List[Range], initial_address_set_choice: AddressSetChoice) -> None:
        super().__init__()
        self.master = master
        self.tool_name = tool_name
        self.program = program
        self.address_factory = program.get_address_factory()
        self.selection_address_set = selection_address_set if selection_address_set else []
        self.has_selection = bool(selection_address_set)
        self.my_initial_address_set = my_initial_address_set if my_initial_address_set else []
        self.initial_address_set_choice = initial_address_set_choice
        self.current_address_set_choice = AddressSetChoice.ENTIRE_PROGRAM

    def create_choose_source_panel(self) -> tk.Frame:
        choose_source_panel = tk.Frame()
        origin_group = tk.Variable()

        entire_program_button = tk.Radiobutton(choose_source_panel, text="Use Entire " + self.tool_name + " Program", variable=origin_group, value=0)
        tool_selection_button = tk.Radiobutton(choose_source_panel, text="Use " + self.tool_name + "'s Selection", variable=origin_group, value=1)
        my_ranges_button = tk.Radiobutton(choose_source_panel, text="Specify My Own Address Ranges", variable=origin_group, value=2)

        entire_program_button.config(command=lambda: self.chose_entire_program())
        tool_selection_button.config(command=lambda: self.chose_tool_selection())
        my_ranges_button.config(command=lambda: self.chose_my_ranges())

        choose_source_panel.pack()

    def chose_entire_program(self) -> None:
        self.current_address_set_choice = AddressSetChoice.ENTIRE_PROGRAM
        self.validate_add_remove_button()
        self.list_frame.entry.configure(state='disabled')
        self.remove_range_button.config(state='disabled')

    def chose_tool_selection(self) -> None:
        self.current_address_set_choice = AddressSetChoice.SELECTION
        self.validate_add_remove_button()
        self.list_frame.entry.configure(state='disabled')
        self.remove_range_button.config(state='disabled')

    def chose_my_ranges(self) -> None:
        self.current_address_set_choice = AddressSetChoice.MANUALLY_DEFINED
        self.validate_add_remove_button()
        self.list_frame.entry.configure(state='normal')
        self.remove_range_button.config(state='normal')

    def set_address_set(self, address_set: List[Range]) -> None:
        self.list_model.set_data(address_set)
        self.list.clear_selection()
        self.notify_listeners()

    def create_remove_range_panel(self) -> tk.Frame:
        remove_range_frame = tk.Frame()
        self.remove_range_button = tk.Button(remove_range_frame, text="Remove Selected Range(s)", command=lambda: self.remove_range())
        self.remove_range_button.config(state='disabled')

        return remove_range_frame

    def show_add_range_dialog(self) -> None:
        add_listener = AddressRangeListener()

        dialog = AddRemoveAddressRangeDialog("Add", self.tool_name, self.program, add_listener)
        self.master.show_dialog(dialog)

    def show_subtract_range_dialog(self) -> None:
        subtract_listener = AddressRangeListener()

        dialog = AddRemoveAddressRangeDialog("Remove", self.tool_name, self.program, subtract_listener)
        self.master.show_dialog(dialog)

    def get_address_set_view(self) -> List[Range]:
        return [range for range in self.my_current_address_set]

    def is_using_selection(self) -> bool:
        return tool_selection_button.instate(['selected'])

    def remove_range(self) -> None:
        selected_indices = list(map(int, self.list.get_selected_indices()))
        address_ranges_to_remove = []

        for i in selected_indices:
            range_ = self.list_model.get_element_at(i)
            address_ranges_to_remove.append(range_)
        
        self.my_current_address_set.delete(address_ranges_to_remove)
        self.list_model.set_data(self.my_current_address_set)
        self.list.clear_selection()
        self.notify_listeners()

    def add_range(self, min_address: Address, max_address: Address) -> None:
        self.my_current_address_set.add_range(min_address, max_address)
        self.list_model.set_data(self.my_current_address_set)
        self.notify_listeners()

    def subtract_range(self, min_address: Address, max_address: Address) -> None:
        self.my_current_address_set.delete_range(min_address, max_address)
        self.list_model.set_data(self.my_current_address_set)
        self.notify_listeners()

    def notify_listeners(self) -> None:
        for listener in self.listeners:
            listener.state_changed(tk.Event())

    def add_change_listener(self, listener: tk.ChangeListener) -> None:
        self.listeners.append(listener)

    def remove_change_listener(self, listener: tk.ChangeListener) -> None:
        if listener in self.listeners:
            self.listeners.remove(listener)
```

Please note that this is a translation of the Java code into Python. It may not be perfect and might require some adjustments to work correctly with your specific use case.