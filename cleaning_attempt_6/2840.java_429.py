class Rectangle2DDirection:
    LEFTMOST = (False,)
    RIGHTMOST = (True,)
    BOTTOMMOST = (False,)
    TOPMOST = (True,)

    def __init__(self, reversed):
        self.reversed = reversed

    @property
    def is_reversed(self):
        return self.reversed


# Example usage:
direction1 = Rectangle2DDirection(*Rectangle2DDirection.LEFTMOST)
print(direction1.is_reversed)  # Output: False

direction2 = Rectangle2DDirection(*Rectangle2DDirection.RIGHTMOST)
print(direction2.is_reversed)  # Output: True
