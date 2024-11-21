Here is the translation of the Java code into Python:

```Python
class PasteAction:
    def __init__(self, plugin):
        self.plugin = plugin
        self.clipboard = plugin.get_clipboard()
        self.tool = plugin.get_tool()

    @property
    def name(self):
        return "Paste"

    @property
    def tooltip(self):
        return f"Paste {self.name}"

    def is_add_to_popup(self, context):
        node = self.get_selected_data_type_node(context)
        if isinstance(node, BuiltInArchiveNode):
            return False

        return node is not None

    def is_enabled_for_context(self, context):
        node = self.get_selected_data_type_node(context)

        if not (isinstance(node, CategoryNode) and node.is_enabled()):
            return False

        transfer_nodes_list = self.get_nodes_from_clipboard()
        return self.can_paste(node, transfer_nodes_list)

    def get_selected_data_type_node(self, context):
        if not isinstance(context, DataTypesActionContext):
            return None

        g_tree = context.get_context_object()

        selection_paths = g_tree.get_selection_paths()
        if selection_paths is None or len(selection_paths) == 0:
            return None

        if len(selection_paths) > 1:
            return None

        node = selection_paths[0].get_last_path_component()
        return node

    def can_paste(self, destination_node, transfer_nodes_list):
        if not transfer_nodes_list:
            return False

        if self.invalid_cut_nodes(destination_node, transfer_nodes_list):
            return False

        provider = self.plugin.get_provider()
        tree = provider.get_g_tree()
        handler = tree.get_drag_ndrop_handler()

        if not destination_node.can_paste(transfer_nodes_list):
            return False

        flavors = handler.get_supported_data_flavors(transfer_nodes_list)
        return handler.is_drop_site_ok(destination_node, flavors, DnDConstants.ACTION_COPY)

    def invalid_cut_nodes(self, destination_node, transfer_nodes_list):
        node = transfer_nodes_list[0]
        if not isinstance(node, DataTypeTreeNode) or not node.is_cut():
            return False

        archive_node = destination_node.get_archive_node()
        for cut_node in transfer_nodes_list:
            data_type_tree_node = cut_node
            archive_node_cut = data_type_tree_node.get_archive_node()

            if archive_node_cut != archive_node:
                return True  # is invalid

        return False  # is valid, all nodes in the same destination archive

    def get_nodes_from_clipboard(self):
        transferable = self.clipboard.get_contents()
        if isinstance(transferable, GTreeNodeTransferable):
            gt_transferable = transferable
            return gt_transferable.get_all_data()

        return []

    def action_performed(self, context):
        g_tree = context.get_context_object()

        selection_paths = g_tree.get_selection_paths()
        destination_node = selection_paths[0].get_last_path_component()

        node_list = self.get_nodes_from_clipboard()
        if not node_list:
            return

        data_type_tree_node = node_list[0]
        if data_type_tree_node.is_cut():
            # clear cut nodes on paste operation
            self.clipboard.set_contents(None, None)

        action_type = self.get_action_type(data_type_tree_node)
        task = DataTypeTreeCopyMoveTask(destination_node, node_list, action_type,
                                          g_tree, self.plugin.get_conflict_handler())
        self.tool.execute(task, 250)

    def get_action_type(self, paste_node):
        if paste_node.is_cut():
            return ActionType.MOVE

        return ActionType.COPY
```

Note: This translation assumes that the following classes and methods are defined elsewhere in your Python code:

- `BuiltInArchiveNode`
- `CategoryNode`
- `DataTypeTreeNodeTransferable`
- `GTree`
- `DataTypesActionContext`
- `PluginTool`
- `DataTypeManagerPlugin`