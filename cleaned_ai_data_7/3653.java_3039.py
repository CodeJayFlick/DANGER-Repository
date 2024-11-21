class CreateTypeDefAction:
    MAX_DISPLAY_CHAR_LENGTH = 20

    def __init__(self, plugin):
        super().__init__("Create Typedef", plugin)
        self.set_popup_menu_data(["New", "Typedef"], None, "Create")

    def is_add_to_popup(self, context):
        node = self.get_data_type_node(context)
        if node is None:
            return False

        data_type = node.data_type
        data_type_manager = data_type.data_type_manager
        if isinstance(data_type_manager, BuiltInDataTypeManager):
            manager = plugin.program_data_type_manager
            if manager is None:
                return False  # no program open; can't work from the built-in in this case

        return True

    def is_enabled_for_context(self, context):
        node = self.get_data_type_node(context)
        if node is None:
            return False

        archive_node = node.archive_node
        if archive_node is None:  # this can happen as the tree is changing
            return False

        enabled = archive_node.is_modifiable()
        if isinstance(archive_node, BuiltInArchiveNode):
            enabled = True

        if enabled:
            dt_name = node.name
            dt_name = StringUtilities.trim(dt_name, self.MAX_DISPLAY_CHAR_LENGTH)
            new_menu_data = MenuData(["New", "Typedef on " + dt_name], None, "Create")
            self.set_popup_menu_data(new_menu_data)

        return enabled

    def get_data_type_node(self, context):
        if not isinstance(context, DataTypesActionContext):
            return None

        context_object = context.context_object
        gtree = GTree(context_object)
        selection_paths = gtree.selection_paths
        if len(selection_paths) != 1:
            return None

        node = selection_paths[0].last_component()
        if not isinstance(node, DataTypeNode):
            return None

        return node

    def action_performed(self, context):
        g_tree = GTree(context.context_object)
        selection_paths = g_tree.selection_paths
        data_type_node = selection_paths[0].last_component()
        data_type = data_type_node.data_type

        base_name = self.get_base_name(data_type) + "Typedef"
        info = DerivativeDataTypeInfo(self.plugin, g_tree, data_type_node, data_type)

        data_type_manager = info.data_type_manager
        name = data_type_manager.unique_name(data_type.category_path(), base_name)

        category_path = info.category_path
        new_data_type = self.create_typedef(data_type_manager, data_type, category_path, context,
                                             data_type_node.parent, name)
        if new_data_type is None:
            return

        final_parent_node = info.parent_node
        new_node_name = new_data_type.name
        g_tree.start_editing(final_parent_node, new_node_name)

    def get_base_name(self, dt):
        if isinstance(dt, Pointer):
            data_type = (dt).data_type
            if data_type is None:
                # must be a generic pointer type
                return dt.name

            return self.get_base_name(data_type) + "Ptr"

        return dt.display_name


class MenuData:
    def __init__(self, items=None, parent_menu_item=None, text=""):
        self.items = items if items is not None else []
        self.parent_menu_item = parent_menu_item
        self.text = text

    @property
    def items(self):
        return self._items

    @items.setter
    def items(self, value):
        self._items = value


class GTree:
    def __init__(self, context_object):
        self.context_object = context_object
        self.selection_paths = []

    @property
    def selection_paths(self):
        return self._selection_paths

    @selection_paths.setter
    def selection_paths(self, value):
        self._selection_paths = value


class GTreeNode:
    pass


class DataTypeNode(GTreeNode):
    def __init__(self, name="", data_type=None, archive_node=None):
        self.name = name
        self.data_type = data_type
        self.archive_node = archive_node

    @property
    def parent(self):
        return None  # this should be implemented in the actual code


class DerivativeDataTypeInfo:
    def __init__(self, plugin, g_tree, node, dt):
        self.plugin = plugin
        self.g_tree = g_tree
        self.node = node
        self.dt = dt

    @property
    def data_type_manager(self):
        return None  # this should be implemented in the actual code

    @property
    def category_path(self):
        return None  # this should be implemented in the actual code

    @property
    def parent_node(self):
        return None  # this should be implemented in the actual code


class BuiltInDataTypeManager:
    pass


class Pointer:
    def __init__(self, data_type=None):
        self.data_type = data_type

    @property
    def data_type(self):
        return self._data_type

    @data_type.setter
    def data_type(self, value):
        self._data_type = value


def create_typedef(data_type_manager, dt, category_path, context, parent_node, name):
    # this should be implemented in the actual code
    pass


class DataTypesActionContext:
    pass
