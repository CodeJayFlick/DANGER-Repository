class StorageGroupCounter:
    def __init__(self, start_node: 'IMNode', path: 'PartialPath') -> None:
        super().__init__(start_node, path)

    def process_internal_matched_mnode(self, node: 'IMNode', idx: int, level: int) -> bool:
        return node.is_storage_group()

    def process_full_matched_mnode(self, node: 'IMNode', idx: int, level: int) -> bool:
        if node.is_storage_group():
            self.count += 1
            return True
        else:
            return False

class IMNode:
    # assume you have a way to check if an MNode is a storage group
    def is_storage_group(self):
        pass

class PartialPath:
    # assume you have some implementation for this class
    pass
