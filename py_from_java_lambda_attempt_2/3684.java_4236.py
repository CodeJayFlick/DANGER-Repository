Here is the translation of the given Java code into Python:

```Python
class PackSizeDataTypeAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Pack Size Data Type", plugin.name)
        self.set_popup_menu_data(["Pack for Size...", "Edit"])

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

        tree_path = selection_paths[0]
        data_type_node = tree_path.get_last_component()
        data_type = data_type_node.get_data_type()
        data_type_manager = data_type.get_data_type_manager()

        if not data_type_manager:
            Msg.error(self, f"Can't pack data type {data_type.name} without a data type manager.")
            return

        number_input_dialog = NumberInputDialog("explicit pack value", 0, 0, 16)
        if not number_input_dialog.show():
            return

        pack_size = number_input_dialog.get_value()

        transaction_id = -1
        commit = False
        try:
            # start a transaction
            transaction_id = data_type_manager.start_transaction(f"pack({pack_size}) of {data_type.name}")
            self.pack_data_type(data_type, pack_size)
            commit = True

        except Exception as e:
            Msg.show_error(self, None, "Invalid Pack Value", str(e))

        finally:
            # commit the changes
            data_type_manager.end_transaction(transaction_id, commit)


    def pack_data_type(self, data_type, pack_size):
        if not isinstance(data_type, Composite):
            Msg.error(self, f"Can't pack data type {data_type.name}. It's not a composite.")
            return

        (Composite)(data_type).pack(pack_size)
```

Note: Python does not have direct equivalent of Java classes like `GTree`, `NumberInputDialog` etc. These are custom or third-party libraries in Java, which you would need to implement yourself if porting the code directly from Java to Python.