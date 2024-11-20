Here is the translation of the Java code into Python:

```Python
class OptionDialogBuilder:
    def __init__(self):
        self.title = None
        self.message = None
        self.icon = None
        self.message_type = 0
        self.add_cancel_button = False
        self.options = []
        self.default_option = None
        self.remember_option = None

    def set_title(self, title: str) -> 'OptionDialogBuilder':
        self.title = title
        return self

    def set_message(self, message: str) -> 'OptionDialogBuilder':
        self.message = message
        return self

    def set_icon(self, icon: object) -> 'OptionDialogBuilder':
        self.icon = icon
        return self

    def set_message_type(self, message_type: int) -> 'OptionDialogBuilder':
        self.message_type = message_type
        return self

    def add_cancel_button(self) -> 'OptionDialogBuilder':
        self.add_cancel_button = True
        return self

    def add_option(self, option_name: str) -> 'OptionDialogBuilder':
        self.options.append(option_name)
        return self

    def set_default_button(self, default_option: str) -> 'OptionDialogBuilder':
        self.default_option = default_option
        return self

    def add_apply_to_all_option(self) -> 'OptionDialogBuilder':
        if not self.remember_option:
            self.remember_option = DialogRememberOption("Apply to all")
        return self

    def add_dont_show_again_option(self) -> 'OptionDialogBuilder':
        if not self.remember_option:
            self.remember_option = DialogRememberOption("Don't show again")
        return self

    def add_remember_my_decision_option(self) -> 'OptionDialogBuilder':
        if not self.remember_option:
            self.remember_option = DialogRememberOption("Remember my decision")
        return self

    def build(self) -> object:
        from ghidra.util.swing import run_now
        return run_now(lambda: OptionDialog(self.title, self.message, self.message_type, self.icon,
                                               self.add_cancel_button, self.remember_option, self.options, self.default_option))

    def show(self, parent=None) -> int:
        if self.remember_option and self.remember_option.has_remembered_result():
            return self.remember_option.get_remembered_result()

        dialog = self.build()
        result = dialog.show(parent)
        return result


class DialogRememberOption:
    def __init__(self, option_name: str):
        self.option_name = option_name
        self.remembered_result = None

    def has_remembered_result(self) -> bool:
        return self.remembered_result is not None

    def get_remembered_result(self) -> int:
        return self.remembered_result


class OptionDialog:
    def __init__(self, title: str, message: str, message_type: int, icon: object, add_cancel_button: bool,
                 remember_option: DialogRememberOption, options: list[str], default_option: str):
        pass

    def show(self, parent=None) -> int:
        # implement the logic to display and get result from OptionDialog
        pass


# usage example
builder = OptionDialogBuilder()
dialog = builder.set_title("Title").set_message("Message").add_cancel_button().build()
result = dialog.show()  # or you can specify a parent component like this: dialog.show(parent_component)
```

Please note that the `OptionDialog` class is not fully implemented in Python as it requires some GUI-related functionality which might be different depending on your chosen framework (e.g., Tkinter, PyQt, etc.).