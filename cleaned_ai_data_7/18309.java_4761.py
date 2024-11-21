class Pair:
    def __init__(self, left, right):
        self.left = left
        self.right = right

    def __hash__(self):
        return hash((self.left, self.right))

    def __eq__(self, other):
        if isinstance(other, type(self)):
            return (self.left == other.left and self.right == other.right)
        else:
            return NotImplemented

    def __str__(self):
        return f"<{self.left}, {self.right}>"
