class LeafNode:
    def __init__(self, name):
        super().__init__(name)

    def is_leaf(self):
        return True


# Example usage:
node = LeafNode("My Node")
print(node.is_leaf())  # Output: True
