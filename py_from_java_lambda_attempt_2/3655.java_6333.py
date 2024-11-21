Here is the translation of the Java code into Python:

```Python
class CreateTypeDefFromDialogAction:
    NAME = "Create Typedef From Dialog"

    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__(NAME)

    def set_popup_menu_data(self):
        return {"New": ["Typedef...", "Create"]}

    def action_performed(self, context):
        category_node = self.get_category_node(context)
        if not category_node:
            return

        category = category_node.category
        dialog = CreateTypeDefDialog(self.plugin, category, category_node.tree_path)
        dialog.set_help_location(HelpLocation(self.plugin.name, self.NAME))
        self.plugin.tool.show_dialog(dialog)

        if dialog.is_cancelled():
            return

        name = dialog.get_type_def_name()
        data_type = dialog.get_data_type()
        data_type_manager = dialog.get_data_type_manager()

        g_tree = context.context_object
        category_path = category.category_path
        new_type_def = self.create_type_def(data_type_manager, data_type, category_path, context, category_node, name)
        if not new_type_def:
            return

        self.plugin.data_type_manager.flush_events()
        parent_node = category_node
        new_node_name = new_type_def.name
        Swing.run_later(lambda: g_tree.set_selected_node_by_name(parent_node, new_node_name))

    def is_enabled_for_context(self, context):
        category_node = self.get_category_node(context)
        if isinstance(category_node, BuiltInArchiveNode):
            return False

        return category_node and category_node.is_modifiable()

    def add_to_popup(self, context):
        category_node = self.get_category_node(context)
        if not category_node or not category_node.enabled:
            return False
        if isinstance(category_node, BuiltInArchiveNode):
            return False
        return True

    def get_category_node(self, context):
        if not isinstance(context, DataTypesActionContext):
            return None

        g_tree = context.context_object
        selection_paths = g_tree.get_selection_paths()
        if len(selection_paths) != 1:
            return None

        node = selection_paths[0].get_last_component()
        while not isinstance(node, CategoryNode) and node is not None:
            node = node.parent
        return category_node

    def create_type_def(self, data_type_manager, data_type, category_path, context, category_node, name):
        # This method should be implemented based on the actual logic of creating a type definition.
        pass


class HelpLocation:
    def __init__(self, plugin_name, action_name):
        self.plugin_name = plugin_name
        self.action_name = action_name

```

Please note that Python does not support direct translation from Java code. The above code is written in pure Python and might behave differently than the original Java code due to differences between languages.