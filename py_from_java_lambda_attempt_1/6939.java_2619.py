Here is the translation of the given Java code into Python:

```Python
class SelectAllAction:
    def __init__(self, owner, panel):
        self.panel = panel
        super().__init__("Select All", owner)
        self.set_key_binding_data(KeyEvent.VK_A, InputEvent.CTRL_DOWN_MASK)

        help_location = HelpLocation(HelpTopics.SELECTION, self.get_name())
        self.set_help_location(help_location)

    def perform_action(self, context):
        self.panel.select_all()
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or the concept of classes extending other classes. The equivalent in Python is to define a class and use inheritance by calling the parent class constructor with `super().__init__()`.

Also, note that there are no direct equivalents for Java's `@Override` annotation as it serves more like a documentation purpose than anything else.