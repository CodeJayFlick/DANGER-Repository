Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import messagebox
from typing import List, Any


class MultipleOptionsDialog:
    def __init__(self, title: str, message: str, choices: List[Any], include_select_all_box: bool):
        self.is_canceled = False

        if isinstance(choices[0], str):
            string_choices = [str(choice) for choice in choices]
        else:
            string_choices = []

        actual_choices = choices
        include_select_all = include_select_all_box

        self.setup(message)

    def setup(self, message: str):
        panel = tk.Frame()
        panel.pack(fill="both", expand=True)
        label = tk.Label(panel, text=message)
        label.pack(side=tk.LEFT)

        if include_select_all:
            select_all_group = SelectAllCheckBox()

            select_all_checkbox = tk.Checkbutton(panel, text="[ Select All ]")
            select_all_checkbox.pack(anchor=tk.W)
            panel.pack_propagate(False)

            select_all_group.set_select_all_checkbox(select_all_checkbox)
        else:
            select_all_group = None

        self.select_options = []
        for i in range(len(string_choices)):
            checkbox = tk.Checkbutton(panel, text=string_choices[i])
            checkbox.pack(anchor=tk.W)
            checkbox.deselect()
            panel.pack_propagate(False)

            if include_select_all:
                select_all_group.add_checkbox(checkbox)

            self.select_options.append(checkbox)

        panel.pack(fill="both", expand=True)

    def ok_callback(self):
        choices_made = [actual_choices[i] for i in range(len(actual_choices)) if self.select_options[i].instate(['selected'])]
        self.chosen_by_user = choices_made

        self.close()

    def cancel_callback(self):
        self.is_canceled = True
        self.close()

    def is_canceled(self) -> bool:
        return self.is_canceled

    def get_user_choices(self) -> List[Any]:
        return self.chosen_by_user


class SelectAllCheckBox:
    def __init__(self):
        self.other_boxes = []
        self.select_all_checkbox = None

    def set_select_all_checkbox(self, checkbox: tk.Checkbutton):
        self.select_all_checkbox = checkbox
        self.select_all_checkbox.config(command=lambda: self.on_action())

    def add_checkbox(self, checkbox: tk.Checkbutton):
        checkbox.config(command=lambda: self.on_action())
        self.other_boxes.append(checkbox)

    def on_action(self):
        source = self.select_all_checkbox if hasattr(self, 'select_all_checkbox') else None

        if source is not None:
            if source.instate(['selected']):
                for box in self.other_boxes:
                    if not box.instate(['selected']):
                        box.invoke()
            elif any(box.instate(['selected']) for box in self.other_boxes):
                self.select_all_checkbox.deselect()

    def close(self):
        pass


def main():
    choices = ["Choice 1", "Choice 2", "Choice 3"]
    include_select_all_box = True

    dialog = MultipleOptionsDialog("Title", "Message", choices, include_select_all_box)
    panel = tk.Frame()
    panel.pack(fill="both", expand=True)

    ok_button = tk.Button(panel, text="OK")
    cancel_button = tk.Button(panel, text="Cancel")

    ok_button.config(command=dialog.ok_callback())
    cancel_button.config(command=dialog.cancel_callback())

    panel.pack_propagate(False)
    panel.pack(fill="both", expand=True)


if __name__ == "__main__":
    main()
```

This Python code is a direct translation of the Java code. It uses tkinter for GUI operations and does not include any error handling or additional functionality that might be present in the original Java code.