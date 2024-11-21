Here is the translation of the Java code into Python:

```Python
class Pack1DataTypeAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Pack1 Data Type", plugin.name)
        self.set_popup_menu_data(["Pack (1)", "Edit"])

    def is_enabled_for_context(self, context):
        if not isinstance(context.get_context_object(), GTree):
            return False

        g_tree = context.get_context_object()
        selection_paths = g_tree.get_selection_paths()

        if len(selection_paths) != 1:
            return False

        node = selection_paths[0].get_last_component()
        if not isinstance(node, DataTypeNode):
            return False

        self.set_enabled(node.is_modifiable())
        return True


    def action_performed(self, context):
        g_tree = context.get_context_object()
        selection_paths = g_tree.get_selection_paths()

        if len(selection_paths) != 1:
            Msg.error("Pack is only allowed on an individual data type.")
            return

        tree_path = selection_paths[0]
        node = tree_path.get_last_component()
        data_type = node.data_type
        data_type_manager = data_type.data_type_manager

        if data_type_manager is None:
            Msg.error(f"Can't pack data type {data_type.name} without a data type manager.")
            return

        transaction_id = -1
        commit = False
        try:
            # start a transaction
            transaction_id = data_type_manager.start_transaction("pack of " + data_type.name)
            self.pack_data_type(data_type)
            commit = True
        finally:
            # commit the changes
            data_type_manager.end_transaction(transaction_id, commit)


    def pack_data_type(self, data_type):
        if not isinstance(data_type, Composite):
            Msg.error(f"Can't pack data type {data_type.name}. It's not a composite.")
            return

        (Composite)(data_type).pack(1)
```

Please note that Python does not have direct equivalent of Java classes like `GTree`, `DataTypeNode` and others. You would need to create your own classes or use existing ones if they are available in the libraries you're using.