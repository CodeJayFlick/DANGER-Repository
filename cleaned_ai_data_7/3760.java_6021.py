class DataTypeTreeDeleteTask:
    def __init__(self, plugin: 'DataTypeManagerPlugin', nodes):
        self.plugin = plugin
        self.node_count = len(nodes)
        self.nodes_by_archive = group_nodes_by_archive(filter_list(nodes))

    @staticmethod
    def filter_list(node_list) -> list:
        node_set = set(node_list)
        filtered_list = []
        
        for node in node_set:
            if not contains_ancestor(node_set, node):
                filtered_list.append(node)

        return filtered_list

    @staticmethod
    def group_nodes_by_archive(nodes: list) -> dict:
        archive_node_map = {}
        
        for node in nodes:
            archive_node = (node).get_archive_node()
            archive_node_list = archive_node_map.get(archive_node)
            
            if archive_node_list is None:
                archive_node_list = []
                archive_node_map[archive_node] = archive_node_list
            else:
                archive_node_list.append(node)

        return archive_node_map

    @staticmethod
    def contains_ancestor(node_set: set, node) -> bool:
        parent = node.get_parent()
        
        if parent is None:
            return False
        
        if node_set.contains(parent):
            return True
        
        return contains_ancestor(node_set, parent)

    def run(self, monitor):
        total = 0
        for archive_nodes in self.nodes_by_archive.values():
            total += len(archive_nodes)
            
        monitor.initialize(total)

        provider = self.plugin.get_provider()
        tree = provider.get_g_tree()
        tree_state = tree.get_tree_state()

        try:
            if self.node_count > NODE_COUNT_FOR_COLLAPSING_TREE:
                collapse_archives(tree, monitor)

            for archive_node, nodes in self.nodes_by_archive.items():
                delete_nodes(archive_node, nodes, monitor)
                
        except CancelledException as e:
            pass

        finally:
            tree.restore_tree_state(tree_state)

    @staticmethod
    def collapse_archives(tree: 'DataTypeArchiveGTree', monitor):
        root = tree.get_model_root()
        children = root.get_children()

        for archive in children:
            tree.collapse_all(archive, monitor)
            
    @staticmethod
    def delete_nodes(archive_node, nodes, monitor) -> None:
        try:
            for node in nodes:
                if not monitor.check_canceled():
                    remove_node(node, monitor)

                monitor.increment_progress()
                
        except CancelledException as e:
            pass

    @staticmethod
    def remove_node(node: 'GTreeNode', monitor):
        if isinstance(node, DataTypeNode):
            data_type = node.get_data_type()
            
            try:
                data_type_manager = data_type.get_data_type_manager()
                data_type_manager.remove(data_type, monitor)
                
            except CancelledException as e:
                pass
        else:
            category_node = CategoryNode(node)
            category = category_node.get_category()

            if not monitor.check_canceled():
                category.get_parent().remove_category(category.name(), monitor)

    NODE_COUNT_FOR_COLLAPSING_TREE = 100

# Usage example:

class DataTypeManagerPlugin:
    def get_provider(self) -> 'DataTypesProvider':
        pass

    def get_g_tree(self) -> 'DataTypeArchiveGTree':
        pass
