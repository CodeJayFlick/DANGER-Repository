import collections
from typing import List, Any

class DataTreeDragNDropHandler:
    _active_project_drop_flavor_handler_map = {}
    local_domain_file_tree_flavor = create_local_node_flavor()
    local_domain_file_flavor = create_local_tree_flavor()
    all_supported_flavors = [local_domain_file_tree_flavor, local_domain_file_flavor, 'string']

    def __init__(self, tool: Any, tree: Any, is_active_project: bool):
        self.tool = tool
        self.tree = tree
        self.is_active_project = is_active_project

    @staticmethod
    def create_local_node_flavor():
        try:
            return GenericDataFlavor('application/x-java-jVMLocalObject; class=list', 'Local list of Drag/Drop Project Domain Tree objects')
        except Exception as e:
            print(f"Error: {e}")

    @staticmethod
    def create_local_tree_flavor():
        try:
            return GenericDataFlavor('application/x-java-jVMLocalObject; class=list', 'Local list of Drag/Drop Project Domain objects')
        except Exception as e:
            print(f"Error: {e}")

    def drop(self, destination: Any, transferable: Any, drop_action: int):
        data_flavors = transferable.get_data_flavors()
        for flavor in data_flavors:
            if self._get_flavor_handler(flavor) is not None:
                self._handle_drop(destination, transferable, drop_action, flavor)
                return

    def _handle_drop(self, destination: Any, transferable: Any, drop_action: int, flavor: str):
        try:
            data = transferable.get_data(flavor)
            if isinstance(data, list) and all(isinstance(node, dict) for node in data):
                self._get_flavor_handler(flavor).handle(self.tool, self.tree, destination, data, drop_action)
        except Exception as e:
            print(f"Error: {e}")

    def _get_flavor_handler(self, flavor: str):
        return self._active_project_drop_flavor_handler_map.get(flavor)

    @staticmethod
    def get_supported_drag_actions():
        return 16

    def is_drop_site_ok(self, destination: Any, flavors: List[str], drop_action: int) -> bool:
        if not self.is_active_project:
            return False
        if ToolConstants.NO_ACTIVE_PROJECT == str(destination):
            return False
        return True

    @staticmethod
    def get_supported_data_flavors(transfer_nodes: List[Any]) -> List[str]:
        return DataTreeDragNDropHandler.all_supported_flavors

    @staticmethod
    def _get_transfer_data(flavor: str, transfer_nodes: List[Any]):
        if flavor == 'application/x-java-jVMLocalObject; class=list':
            # this removes files that are already in the list because they are children of folders that are in the list
            return [node for node in transfer_nodes]
        elif flavor == 'application/x-java-jVMLocalObject; class=java.util.List':
            # filter for file nodes and convert each node to its corresponding domainFile
            return [str(node) for node in transfer_nodes if isinstance(node, dict)]
        else:
            raise Exception("Called with a flavor that we didn't say we supported")

    @staticmethod
    def add_active_data_flavor_handler(flavor: str, handler: Any):
        DataTreeDragNDropHandler._active_project_drop_flavor_handler_map[flavor] = handler

    @staticmethod
    def remove_active_data_flavor_handler(flavor: str) -> Any:
        return DataTreeDragNDropHandler._active_project_drop_flavor_handler_map.pop(flavor, None)

    def set_project_active(self, b: bool):
        self.is_active_project = b


class GenericDataFlavor:
    def __init__(self, flavor_string: str, description: str):
        self.flavor_string = flavor_string
        self.description = description

    @staticmethod
    def get_data_flavors():
        return ['application/x-java-jVMLocalObject; class=list', 'application/x-java-jVMLocalObject; class=java.util.List']
