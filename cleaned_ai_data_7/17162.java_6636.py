import collections

class EntityPathCollector:
    def __init__(self, start_node: 'IMNode', path: 'PartialPath') -> None:
        self.start_node = start_node
        self.path = path
        self.result_set = set()

    def __init__(self, start_node: 'IMNode', path: 'PartialPath', limit: int, offset: int) -> None:
        super().__init__(start_node, path)
        self.limit = limit
        self.offset = offset
        self.result_set = set()
        self.count = 0

    def process_internal_matched_mnode(self, node: 'IMNode', idx: int, level: int) -> bool:
        return False

    def process_full_matched_mnode(self, node: 'IMNode', idx: int, level: int) -> bool:
        if node.is_entity():
            self.count += 1
            if self.offset < offset and self.count <= limit:
                return True
            elif self.count > limit:
                return False

            self.result_set.add(node.get_partial_path())
            return True

        return False


class IMNode:
    def is_entity(self) -> bool:
        # TO DO: implement this method
        pass

    def get_partial_path(self) -> 'PartialPath':
        # TO DO: implement this method
        pass
