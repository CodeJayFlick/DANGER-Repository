Here is a translation of the Java code into equivalent Python:

```Python
class InputWithChoicesDialog:
    def __init__(self, dialog_title: str, label_text: str, option_values: list[str], 
                 initial_value: str | None = None, allow_edits: bool = False) -> None:
        self.is_canceled = False
        self.combo_box = GhidraComboBox(option_values)
        self.allow_edits = allow_edits

    def build_main_panel(self, label_text: str, option_values: list[str], initial_value: str | None = None, 
                          message_icon: Icon | None = None) -> JPanel:
        work_panel = JPanel()
        data_panel = JPanel()

        if message_icon is not None:
            icon_label = GDLabel(message_icon)
            separator_panel = JPanel()
            separator_panel.setPreferredSize(Dimension(15, 1))
            icon_panel = JPanel()
            icon_panel.add(icon_label, BorderLayout.CENTER)
            icon_panel.add(separator_panel, BorderLayout.EAST)

            work_panel.add(icon_panel, BorderLayout.WEST)

        data_panel.add(GHtmlLabel(label_text), BorderLayout.NORTH)
        self.combo_box.set_editable(self.allow_edits)
        if initial_value is not None:
            self.combo_box.set_selected_item(initial_value)
        data_panel.add(self.combo_box, BorderLayout.SOUTH)

        work_panel.add(data_panel, BorderLayout.CENTER)

        return work_panel

    def ok_callback(self) -> None:
        self.is_canceled = False
        close()

    def cancel_callback(self) -> None:
        self.is_canceled = True
        close()

    @property
    def is_canceled(self) -> bool:
        return self._is_canceled

    @is_canceled.setter
    def is_canceled(self, value: bool) -> None:
        if not isinstance(value, bool):
            raise TypeError("Expected a boolean")
        self._is_canceled = value

    def get_value(self) -> str | None:
        if self.is_canceled:
            return None
        selected_item = self.combo_box.get_selected_item()
        return selected_item if selected_item is not None else None

    def set_value(self, value: str) -> None:
        try:
            self.combo_box.set_selected_item(value)
        except NoSuchElementException as e:
            raise e from ValueError("Invalid choice")
```

Please note that Python does not have direct equivalent of Java's Swing library. The code above is a translation of the provided Java code into Python, but it may require additional libraries or modifications to work correctly in your specific use case.

Also, please be aware that some parts of this code are quite complex and might need further adjustments based on how you plan to integrate them with other components of your application.