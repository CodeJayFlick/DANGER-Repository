Here is the translation of the Java code into Python:

```Python
class CollapseAllArchivesAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Collapse All", plugin.get_name())
        update_popup_menu(False)
        set_toolbar_data(ToolBarData(Icons.COLLAPSE_ALL_ICON, None))
        set_key_binding_data(KeyBindingData(KeyEvent.VK_UP, InputEvent.ALT_DOWN_MASK))
        set_enabled(True)
        self.description = "Collapse All Data Types for Program and Archives"

    def update_popup_menu(self, is_single_node_selected):
        if is_single_node_selected:
            popup_menu_data = MenuData(["Collapse"], Icons.COLLAPSE_ALL_ICON, "Tree")
        else:
            popup_menu_data = MenuData(["Collapse All"], Icons.COLLAPSE_ALL_ICON, "Tree")
        self.set_popup_menu_data(popup_menu_data)

    def is_add_to_popup(self, context):
        if not isinstance(context, DataTypesActionContext):
            return False
        gtree = context.get_context_object()
        selection_paths = gtree.get_selection_paths()
        has_leaf_node = is_leaf_node_selection(selection_paths)
        if has_leaf_node:
            # don't add to menu when the only item selected has no children
            return len(selection_paths) != 1
        return True

    def is_enabled_for_context(self, context):
        if not isinstance(context, DataTypesActionContext):
            self.update_popup_menu(False)
            return False
        gtree = context.get_context_object()
        selection_paths = gtree.get_selection_paths()
        if len(selection_paths) == 0:
            # Collapse All when nothing is selected
            self.update_popup_menu(False)
        elif len(selection_paths) == 1:
            # collapse single node with children
            self.update_popup_menu(True)
        else:
            # Collapse All when multiple nodes
            self.update_popup_menu(False)
        return True

    def is_leaf_node_selection(self, selection_paths):
        for path in selection_paths:
            node = path.get_last_path_component()
            if isinstance(node, GTreeNode) and not node.is_leaf():
                return False
        return True

    def action_performed(self, context):
        # This actions does double duty.  When invoked from the icon, it closes all nodes.
        # When invoked from the popup, it only closes selected nodes.

        if not isinstance(context, DataTypesActionContext):
            self.collapse_all(plugin.get_provider().get_gtree())  # on the toolbar or filter field--collapse all
        elif context.is_toolbar_action():
            self.collapse_all(plugin.get_provider().get_gtree())  # on the toolbar or filter field--collapse all
        else:
            gtree = context.get_context_object()
            selection_paths = gtree.get_selection_paths()
            if selection_paths is None or len(selection_paths) != 1:
                # no paths selected; close all paths
                self.collapse_all(plugin.get_provider().get_gtree())
            elif isinstance(selection_paths[0], TreePath):
                for path in selection_paths:
                    node = path.get_last_path_component()
                    if isinstance(node, GTreeNode) and not node.is_leaf():
                        gtree.collapse_all(node)
        return

    def collapse_all(self, archive_gtree):
        root_node = archive_gtree.view_root
        children = list(root_node.children())
        for child in children:
            self.collapse_all(child)

class TreePath:
    pass

class GTreeNode:
    def is_leaf(self):
        # This method should return True if the node has no children, False otherwise.
        pass

class ToolBarData:
    def __init__(self, icon, tooltip):
        self.icon = icon
        self.tooltip = tooltip

class KeyBindingData:
    def __init__(self, key_code, modifiers):
        self.key_code = key_code
        self.modifiers = modifiers

class MenuData:
    def __init__(self, items, icon, tooltip):
        self.items = items
        self.icon = icon
        self.tooltip = tooltip

Icons.COLLAPSE_ALL_ICON  # This should be replaced with the actual collapse all icon.
```

Please note that Python does not have direct equivalent of Java's Swing and AWT libraries. The code above is a translation, but it may require additional work to make it fully functional in Python.