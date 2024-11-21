class MNodeCollector:
    def __init__(self, start_node, path):
        pass  # Initialize with start node and path

    def traverse(self, node, idx, level):
        if self.storage_group_filter and node.is_storage_group() and not self.storage_group_filter.satisfy(node.get_full_path()):
            return
        super().traverse(node, idx, level)

    def process_internal_matched_m_node(self, node, idx, level):
        return False  # Return false for internal matched MNode

    def process_full_matched_m_node(self, node, idx, level):
        if self.target_level > 0:
            if level == self.target_level:
                self.transfer_to_result(node)
                return True
        else:
            self.transfer_to_result(node)
        return False

    def transfer_to_result(self, node):  # Abstract method to be implemented by subclasses
        pass

    @property
    def storage_group_filter(self):
        return self._storage_group_filter

    @storage_group_filter.setter
    def storage_group_filter(self, value):
        self._storage_group_filter = value

    @property
    def target_level(self):
        return self._target_level

    @target_level.setter
    def target_level(self, value):
        self._target_level = value


class IMNode:
    def is_storage_group(self):  # Method to check if node is a storage group
        pass

    def get_full_path(self):  # Method to return the full path of the node
        pass


# Example usage:

start_node = IMNode()  # Initialize start node and partial path
path = PartialPath()

collector = MNodeCollector(start_node, path)
collector.storage_group_filter = StorageGroupFilter()
collector.target_level = 1

collector.traverse(start_node, 0, 0)  # Traverse the tree starting from the given node
