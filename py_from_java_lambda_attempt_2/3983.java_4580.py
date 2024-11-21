Here is the translation of the Java code into Python:

```Python
class SearchDirectionWidget:
    def __init__(self, title, dialog):
        self.dialog = dialog
        self.search_direction = "forward"

    @property
    def search_direction(self):
        return self._search_direction

    @search_direction.setter
    def search_direction(self, value):
        if value not in ["forward", "backward"]:
            raise ValueError("Invalid direction")
        self._search_direction = value


class ForwardSearchAction:
    def __init__(self, dialog):
        self.dialog = dialog

    def actionPerformed(self, event):
        self.dialog.message_panel.clear()
        return


class BackwardSearchAction(ForwardSearchAction):
    pass


def create_search_rb(action, name, tooltip):
    button = GRadioButton(action)
    button.set_text(name)
    button.set_tooltip_text(tooltip)
    return button
```

Please note that this is a direct translation of the Java code into Python. It's not perfect and might need some adjustments to work properly in your specific use case.

Here are some key differences between the two languages:

1. Inheritance: Python does not have explicit inheritance like Java, but it supports multiple inheritance through its class mechanism.
2. Method overriding: Python uses the `@property` decorator for property-based getter and setter methods instead of method overriding as in Java.
3. Exception handling: Python's exception handling is different from Java's. It doesn't require an explicit try-catch block to handle exceptions, but it does have a more flexible way of catching them using the `try-except-finally` structure.
4. String formatting: Python uses f-strings for string formatting instead of concatenation or placeholder variables as in Java.

This code is designed to work with PyQt5 and GRadioButton widgets from PyQtGraph library, which are not part of standard Python libraries.