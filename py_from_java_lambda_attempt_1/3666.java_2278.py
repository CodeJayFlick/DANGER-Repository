Here is the translation of the Java code into Python:

```Python
class ExpandAllAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Expand All", self.plugin.get_name())

        menu_data = {"menu_items": ["Expand"], "icon": Icons.EXPAND_ALL_ICON, "popup_title": "Tree"}
        key_binding_data = {"key_event": KeyEvent.VK_DOWN, "mask": InputEvent.ALT_DOWN_MASK}
        self.set_popup_menu_data(menu_data)
        self.set_key_binding_data(key_binding_data)

        self.enabled = True
        self.description = "Recursively expand all selected nodes."

    def is_enabled_for_context(self, context):
        if not isinstance(context, DataTypesActionContext):
            return False

        gtree = context.get_context_object()
        selection_paths = gtree.get_selection_paths()

        if len(selection_paths) == 0:
            return False

        for path in selection_paths:
            node = path.get_last_component()
            if node.is_leaf():
                return False
        return True

    def action_performed(self, context):
        g_tree = context.get_context_object()
        selection_paths = g_tree.get_selection_paths()

        for path in selection_paths:
            node = path.get_last_component()
            g_tree.expand_tree(node)
```

Please note that this is a direct translation of the Java code into Python. The original code seems to be part of a larger program, and some parts might not work as-is in Python (like `Icons.EXPAND_ALL_ICON` or `InputEvent.ALT_DOWN_MASK`).