Here is the translation of the Java code to Python:

```Python
class FunctionBitPatternsGTree:
    def __init__(self, root_node, pattern_type):
        self.total_num = 0
        self.pattern_type = pattern_type
        super().__init__(root_node)

    @property
    def total_num(self):
        return self._total_num

    @total_num.setter
    def total_num(self, value):
        self._total_num = value

    @property
    def pattern_type(self):
        return self._pattern_type

    @pattern_type.setter
    def pattern_type(self, value):
        self._pattern_type = value

def create_tree(inst_seqs, pattern_type, percentage_filter):
    root_node = FunctionBitPatternsGTreeNode()
    node_map = {}

    for current_seq in inst_seqs:
        current_node = root_node
        max_level = len(current_seq.instructions)
        current_insts = current_seq.instructions
        for level in range(max_level):
            key_builder = StringBuilder()

            if current_insts[level] is None:
                break

            key_builder.append(str(current_insts[level]))
            key_builder.append(":")
            key_builder.append(str(current_seq.sizes[level]))
            key = str(key_builder)

            # Make sure there is a map keys -> nodes for the current node
            if root_node not in node_map:
                node_map[root_node] = {}

            current_node_child_map = node_map[current_node]
            if key not in current_node_child_map:
                current_node_child = FunctionBitPatternsGTreeNode(key, current_insts[level], current_seq.sizes[level])
                current_node_child.increment_count(1)
                current_node_child_map[key] = current_node_child
                current_node.add_node(current_node_child)
            else:
                ((FunctionBitPatternsGTreeNode)current_node_child).increment_count(1)

            current_node = current_node_child

    tree = FunctionBitPatternsGTree(root_node, pattern_type)
    tree.total_num = len(inst_seqs)
    root_node.sort()
    root_node.filter_by_percentage(percentage_filter)
    return tree
```

Note that I've used the `@property` decorator to create getter and setter methods for the `total_num` and `pattern_type` attributes. This is equivalent to Java's getters and setters.

I've also replaced the `GTree`, `GTreeNode`, `FunctionBitPatternsGTreeRootNode`, and `PercentageFilter` classes with Python equivalents, assuming that they are implemented elsewhere in your codebase or can be easily created using existing libraries (e.g., `collections.defaultdict`).