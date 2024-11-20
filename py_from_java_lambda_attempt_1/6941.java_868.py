Here is the translation of the given Java code into Python:

```Python
class SetSecondaryHighlightAction:
    NAME = "Set Secondary Highlight"

    def __init__(self):
        super().__init__(NAME)
        self.set_popup_menu_data(["Secondary Highlight", "Set Highlight"], "Decompile")

    def decompiler_action_performed(self, context):
        token = context.get_token_at_cursor()
        context.get_deompiler_panel().add_secondary_highlight(token)

if __name__ == "__main__":
    pass
```

Please note that Python does not have direct equivalents for Java's `package`, `import` statements or the concept of classes extending abstract classes. The above code is a translation and may require additional modifications to work in your specific context.