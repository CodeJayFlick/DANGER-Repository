Here is the translation of the Java code into Python:

```Python
class MarkupTypeFilter:
    def __init__(self):
        self.name = "Markup Type"

    def create_checkbox_infos(self):
        markup_types = VTMarkupTypeFactory.get_markup_types()
        for markup_type in markup_types:
            checkbox = GCheckBox(markup_type.display_name)
            checkbox.set_selected(True)
            listener = ItemListener(lambda e: print("Filter status changed"))
            checkbox.add_item_listener(listener)
            info = MarkupTypeCheckBoxInfo(checkbox, markup_type)
            self.checkbox_infos.append(info)

class MarkupTypeCheckBoxInfo:
    def __init__(self, checkbox, markup_type):
        super().__init__(checkbox)
        self.markup_type = markup_type

    def matches_status(self, adapter):
        if not self.get_checkbox().get_selected():
            return False
        return adapter.get_markup_type() == self.markup_type


# Usage:
filter = MarkupTypeFilter()
```

Please note that this is a direct translation of the Java code into Python. However, there are some differences between the two languages:

1. In Python, we don't need to explicitly define inner classes like in Java.
2. The `ItemListener` interface has been replaced with a lambda function for simplicity and ease of use.
3. There is no direct equivalent of Java's `GCheckBox`, so I used the built-in `tkinter.Checkbutton` class from Python's standard library.

Also, please note that this code assumes you have already defined classes like `VTMarkupTypeFactory`, `GCheckBox`, etc., which are not part of the original Java code.