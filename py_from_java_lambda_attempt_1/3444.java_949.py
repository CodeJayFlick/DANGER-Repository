Here is the translation of the given Java code into Python:

```Python
class AddBookmarkAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Add Bookmark", plugin.name)
        self.setDescription("Add Notes bookmark to current location")

    def set_popup_menu_data(self):
        return {"menu": ["Bookmark...", "Bookmark"]}

    def set_key_binding_data(self):
        return {"keybinding": [(0, 65535), (4,)]}

    def actionPerformed(self, context):
        address = self.get_address(context)
        if address is not None:
            self.plugin.show_add_bookmark_dialog(address)

    def is_enabled_for_context(self, context):
        if context is None:
            return False
        return self.get_address(context) is not None

    def get_address(self, context):
        context_object = context.context_object
        if isinstance(context_object, MarkerLocation):
            return context_object.addr
        elif isinstance(context, ListingActionContext):
            return context.address
        else:
            return None


class BookmarkPlugin:
    pass


# Example usage:

plugin = BookmarkPlugin()
action = AddBookmarkAction(plugin)
```

Please note that Python does not have direct equivalent of Java's `docking. action` and other classes used in the original code, so I had to simplify it a bit. Also, some methods like `setPopupMenuData`, `setKeyBindingData` are just placeholders as there is no direct translation for these in Python.