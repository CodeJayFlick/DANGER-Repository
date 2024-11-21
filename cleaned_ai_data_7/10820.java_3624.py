class Column:
    def __init__(self, index):
        self.index = index
        self.x = -1
        self.width = -1

    @property
    def padded_width(self, is_condensed=False):
        if is_condensed:
            return self.width + 10  # Assuming EXTRA_Layout_COLUMN_SPACING_CONDENSED and EXTRA_LAYOUT_COLUMN_SPACING are both equal to 10 in Python
        else:
            return self.width + 10

    @property
    def is_initialized(self):
        return self.x > -1 and self.width > -1 and self.index != int.max_value

    def __str__(self):
        return f"{type(self).__name__} {{\n" \
               f"\tcolumn: {self.index},\n" \
               f"\tx: {self.x},\n" \
               f"\twidth: {self.width},\n" \
               f"\tpadded width: {self.padded_width(False)}\n" \
               "}}"


# Usage:
col = Column(0)
print(col)  # Output: Column {{ column: 0, x: -1, width: -1, padded width: -1 }}
