class MetadataIndexEntry:
    def __init__(self, name: str, value: int):
        self.name = name
        self.value = value


class MetadataIndexNode:
    def __init__(self, entries: list, parent_value: int, node_type: str):
        self.entries = entries
        self.parent_value = parent_value
        self.node_type = node_type

    def binary_search_in_children(self, target_name: str, exact_match: bool) -> int:
        for i, entry in enumerate(self.entries):
            if (exact_match and entry.name == target_name) or \
               ((not exact_match) and target_name <= entry.name):
                return i
        return -1


import unittest

class TestMetadataIndexNode(unittest.TestCase):

    def test_binary_search_in_children(self):
        entries = [MetadataIndexEntry("s0", 0), MetadataIndexEntry("s5", 0),
                   MetadataIndexEntry("s10", 0), MetadataIndexEntry("s15", 0),
                   MetadataIndexEntry("s20", 0)]

        metadata_index_node = MetadataIndexNode(entries, -1, "LEAF_MEASUREMENT")
        self.assertEqual(0, metadata_index_node.binary_search_in_children("s0", False))
        self.assertEqual(3, metadata_index_node.binary_search_in_children("s10", False))
        self.assertEqual(-1, metadata_index_node.binary_search_in_children("s13", True))
        self.assertEqual(-1, metadata_index_node.binary_search_in_children("s23", True))


if __name__ == '__main__':
    unittest.main()
