import typing as t

class DataTypeDragNDropHandler:
    local_data_type_tree_flavor = create_local_node_flavor()
    all_supported_flavors = [DataTypeTransferable.local_data_type_flavor, local_data_type_tree_flavor]
    builtin_flavors = [DataTypeTransferable.local_builtin_data_type_flavor, local_data_type_tree_flavor]
    restricted_flavors = [local_data_type_tree_flavor]

    def __init__(self, plugin: 'DataTypeManagerPlugin', tree: t.Any) -> None:
        self.plugin = plugin
        self.tree = tree

    @staticmethod
    def create_local_node_flavor() -> t.Any:
        try:
            return GenericDataFlavor("Local list of Drag/Drop DataType Tree objects", "java.util.List")
        except Exception as e:
            Msg.show_error(DataTypeDragNDropHandler, None, None, None, e)
        return None

    def drop(self, destination_node: 'GTreeNode', transferable: t.Any, drop_action: int) -> None:
        try:
            list_nodes = (t.List['GTreeNode']).__getitem__(transferable.get_transfer_data(DataTypeDragNDropHandler.local_data_type_tree_flavor))
            if list_nodes.contains(destination_node):
                return
            action_type = ActionType.COPY if drop_action == DnDConstants.ACTION_COPY else ActionType.MOVE
            task = DataTypeTreeCopyMoveTask(destination_node, list_nodes, action_type, self.tree, self.plugin.get_conflict_handler())
            self.plugin.get_tool().execute(task, 250)
        except UnsupportedFlavorException as e:
            Msg.error(self, "Unable to perform drop operation", e)
        except IOException as e:
            Msg.error(self, "Unable to perform drop operation", e)

    def get_supported_data_flavors(self, dragged_nodes: t.List['GTreeNode']) -> t.Any:
        if len(dragged_nodes) == 1:
            node = dragged_nodes[0]
            if isinstance(node, DataTypeNode):
                data_type = node.get_data_type()
                return all_supported_flavors if not (isinstance(data_type, BuiltInDataType) or isinstance(data_type, MissingBuiltInDataType)) else builtin_flavors
        # we don't support dragging archives in their entirety
        if isinstance(node, ArchiveNode):
            return []
        return restricted_flavors

    def get_supported_drag_actions(self) -> int:
        return DnDConstants.ACTION_COPY_OR_MOVE

    def get_transfer_data(self, drag_user_data: t.List['GTreeNode'], flavor: 'DataFlavor') -> t.Any:
        if flavor == DataTypeTransferable.local_data_type_flavor or flavor == DataTypeTransferable.local_builtin_data_type_flavor:
            node = dragged_nodes[0]
            return node.get_data_type()
        elif flavor == self.local_data_type_tree_flavor:
            return drag_user_data
        elif flavor == DataFlavor.java_file_list_flavor:
            list_node = []
            for node in drag_user_data:
                archive_node = ArchiveNode(node)
                file_archive = FileArchive(archive_node.get_archive())
                resource_file = file_archive.get_file()
                list_node.append(resource_file)
            return list_node
        return None

    def is_drop_site_ok(self, destination_node: 'GTreeNode', flavors: t.List['DataFlavor'], drop_action: int) -> bool:
        if not destination_node or not destination_node.parent:
            return False
        if not contains_flavor(flavors, self.local_data_type_tree_flavor):
            return False
        archive_node = (destination_node).get_archive_node()
        if not archive_node or not archive_node.is_modifiable():
            return False
        if isinstance(destination_node, DataTypeNode):
            if len(flavors) != 1:
                return False
            if flavors[0] == DataFlavor.java_file_list_flavor and drop_action == DnDConstants.ACTION_COPY:
                return True
        return True

    def is_start_drag_ok(self, drag_user_data: t.List['GTreeNode'], drag_action: int) -> bool:
        return True

    @staticmethod
    def contains_flavor(flavors: t.List['DataFlavor'], flavor: 'DataFlavor') -> bool:
        for f in flavors:
            if f == flavor:
                return True
        return False

    @staticmethod
    def is_dropping_builtin(flavors: t.List['DataFlavor']) -> bool:
        for flavor in flavors:
            if flavor == DataTypeTransferable.local_builtin_data_type_flavor:
                return True
        return False

    @staticmethod
    def is_valid_builtin_drop_site(destination_node: 'GTreeNode') -> bool:
        if not isinstance(destination_node, CategoryNode):
            return True
        category_node = (destination_node)
        return isinstance(category_node, ArchiveNode)

class DataTypeTransferable(t.Any):  # This class should be implemented separately.
    local_data_type_flavor = None
    local_builtin_data_type_flavor = None

# The following classes are not defined in the provided code:
class GTreeNode(t.Any):
    pass

class GTree(t.Any):
    pass

class DataTypeNode(GTreeNode):
    def get_data_type(self) -> t.Any:  # This method should be implemented separately.
        pass

class ArchiveNode(GTreeNode):
    def get_archive_node(self) -> 'Archive':  # This method should be implemented separately.
        pass

class CategoryNode(ArchiveNode):  # This class is not defined in the provided code, but it seems to inherit from ArchiveNode.

# The following classes are also not defined:
class DataTypeTreeCopyMoveTask(t.Any):
    def __init__(self) -> None:  # This method should be implemented separately.
        pass

class Task(t.Any):  # This class is not defined in the provided code, but it seems to inherit from some other class.

# The following classes are also not defined:
class DataFlavor(t.Any):
    def __init__(self) -> None:  # This method should be implemented separately.
        pass

class GenericDataFlavor(DataFlavor):  # This class is not defined in the provided code, but it seems to inherit from some other class.

# The following classes are also not defined:
class DataTypeManagerPlugin(t.Any):
    def get_tool(self) -> t.Any:  # This method should be implemented separately.
        pass

    def get_conflict_handler(self) -> t.Any:  # This method should be implemented separately.
        pass
