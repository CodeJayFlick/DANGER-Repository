class BelongedEntityPathCollector:
    def __init__(self, start_node: 'IMNode', path: 'PartialPath') -> None:
        self.result_set = set()
        super().__init__(start_node, path)

    def process_internal_matched_mnode(self, node: 'IMNode', idx: int, level: int) -> bool:
        if not node.is_measurement() or idx != len(self.nodes) - 2:
            return False
        measurement_mnode = node.as_measurement_mnode()
        if measurement_mnode.is_multi_measurement():
            measurements = measurement_mnode.as_multi_measurement_mnode().get_sub_measurement_list()
            regex = self.nodes[idx + 1].replace('*', '.*')
            for measurement in measurements:
                if not re.match(regex, measurement):
                    self.result_set.add(node.parent.get_partial_path())
                    break
        return True

    def process_full_matched_mnode(self, node: 'IMNode', idx: int, level: int) -> bool:
        if not node.is_measurement():
            return False
        measurement_mnode = node.as_measurement_mnode()
        if measurement_mnode.is_unary_measurement():
            self.result_set.add(node.parent.get_partial_path())
        elif measurement_mnode.is_multi_measurement():
            if idx >= len(self.nodes) - 1 and self.nodes[-1] != MULTI_LEVEL_PATH_WILDCARD and not is_prefix_match:
                return True
            self.result_set.add(node.parent.get_partial_path())
        return True

# You need to define IMNode, PartialPath, set, List, Pattern in your Python code.
