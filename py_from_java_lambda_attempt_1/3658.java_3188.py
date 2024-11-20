Here is the translation of the Java code into Python:

```Python
class DeleteAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Delete", plugin.get_name())
        set_popup_menu_data(["Delete"], None, "Edit")
        set_key_binding_data(KeyEvent.VK_DELETE, 0)
        self.set_enabled(True)

    def is_add_to_popup(self, context):
        if not isinstance(context, DataTypesActionContext):
            return False
        selection_paths = get_selection_paths(context)
        if selection_paths is None or len(selection_paths) == 0:
            return False
        if contains_undeletable_nodes(selection_paths):
            return False
        return True

    def is_enabled_for_context(self, context):
        if not isinstance(context, DataTypesActionContext):
            return False
        selection_paths = get_selection_paths(context)
        return can_delete(selection_paths)

    def get_selection_paths(self, context):
        context_object = context.get_context_object()
        gtree = GTree(context_object)
        return gtree.get_selection_paths()

    def contains_undeletable_nodes(self, selection_paths):
        for path in selection_paths:
            node = DataTypeTreeNode(path[-1])
            if not node.can_delete() or isinstance(node, ArchiveNode):
                return True
        return False

    def can_delete(self, selection_paths):
        for path in selection_paths:
            node = DataTypeTreeNode(path[-1])
            if not node.can_cut():
                return False
        return True

    def action_performed(self, context):
        choice = OptionDialog.show_yes_no_dialog_with_no_as_default_button(None,
                                                                           "Confirm Delete Operation",
                                                                           f"Are you sure you want to delete selected\n categories and/or dataTypes?\n(Note: There is no undo for archives.)")
        if choice != OptionDialog.OPTION_ONE:
            return
        gtree = GTree(context.get_context_object())
        selection_paths = gtree.get_selection_paths()
        node_list = [GTreeNode(path[-1]) for path in selection_paths]
        self.plugin.get_tool().execute(DataTypeTreeDeleteTask(self.plugin, node_list), 250)
```

Please note that Python does not have direct equivalent of Java's `ActionContext`, so I had to modify the code slightly. Also, Python does not support checked exceptions like Java, so error handling is different in both languages.