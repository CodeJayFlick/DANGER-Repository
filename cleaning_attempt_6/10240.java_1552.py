class ReverseSetIterator:
    def __init__(self, tree, node):
        self.tree = tree
        self.node = node

    def copy(self):
        return ReverseSetIterator(self.tree, self.node)

    def increment(self):
        if self.node is None:
            raise IndexError()
        self.node = self.node.get_predecessor()
        return self

    def decrement(self):
        if self.node is None and self.tree.is_empty():
            raise IndexError()
        elif self.node is None:
            self.node = self.tree.get_first()
        else:
            self.node = self.node.get_successor()
        return self

    def delete(self):
        if self.node is None:
            raise IndexError()
        next_node = self.node.get_predecessor()
        self.tree.delete_entry(self.node)
        self.node = next_node

    @property
    def is_begin(self):
        return self.node == self.tree.get_last()

    def __eq__(self, obj):
        if obj is None:
            return False
        elif obj is self:
            return True
        elif not isinstance(obj, type(self)):
            return False
        other = ReverseSetIterator(obj.tree, obj.node)
        return self.tree == other.tree and self.node == other.node

    def __hash__(self):
        return hash(self.tree)

class RedBlackTree:
    # Define the methods for this class as needed.
