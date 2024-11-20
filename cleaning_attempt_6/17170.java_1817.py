class EntityCounter:
    def __init__(self, start_node: 'IMNode', path: 'PartialPath') -> None:
        super().__init__(start_node, path)

    def process_internal_matched_mnode(self, node: 'IMNode', idx: int, level: int) -> bool:
        return False

    def process_full_matched_mnode(self, node: 'IMNode', idx: int, level: int) -> bool:
        if node.is_entity():
            self.count += 1
        return False
