class RedBlackEntry:
    class NodeColor:
        RED = 'RED'
        BLACK = 'BLACK'

    def __init__(self, key, value, parent=None):
        self.key = key
        self.value = value
        self.color = RedBlackEntry.NodeColor.BLACK
        self.parent = parent
        self.left = None
        self.right = None

    @property
    def get_value(self):
        return self.value

    @get_value.setter
    def set_value(self, value):
        old_value = self.value
        self.value = value
        return old_value

    @property
    def get_key(self):
        return self.key

    def get_successor(self):
        if self.right:
            node = self.right
            while node.left:
                node = node.left
            return node
        node = self
        while node.parent and not node.is_left_child():
            node = node.parent
        return node.parent or None

    def get_predecessor(self):
        if self.left:
            node = self.left
            while node.right:
                node = node.right
            return node
        node = self
        while node.parent and node.is_left_child():
            node = node.parent
        return node.parent or None

    @property
    def is_left_child(self):
        return self.key == self.parent.left

    @property
    def is_right_child(self):
        return self.key == self.parent.right

    def is_disposed(self):
        return self.color is None


# Example usage:
entry = RedBlackEntry('key', 'value')
print(entry.get_value)  # prints: value
