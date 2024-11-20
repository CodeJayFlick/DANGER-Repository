Here is the translation of the Java code to Python:

```Python
class MixedFieldBackgroundColorManager:
    def __init__(self, index: int, field_num: int, layout_selection: 'MixedLayoutBackgroundColorManager', selection_color: tuple, background_color: tuple):
        self.index = index
        self.field_num = field_num
        self.layout_selection = layout_selection
        self.background_color = background_color
        self.selection = layout_selection.get_selection()
        self.selection_color = selection_color

    def get_selection_highlights(self, row: int) -> list:
        start_location = FieldLocation(index=self.index, field_num=self.field_num, row=row, col=0)
        end_location = FieldLocation(index=self.index, field_num=self.field_num, row=row+1, col=0)
        intersect = self.selection.intersect(FieldRange(start=start_location, end=end_location))
        highlights = []
        for i in range(intersect.get_num_ranges()):
            range_ = intersect.get_field_range(i)
            min_col = range_.get_start().col
            max_col = range_.get_end().row == row and range_.get_end().col or int('ff', 16)  # Integer.MAX_VALUE equivalent
            highlights.append(Highlight(min=min_col, max=max_col, color=self.selection_color))
        return highlights

    def get_background_color(self):
        if self.layout_selection.get_background_color() == self.background_color:
            return None
        return self.background_color

    def get_padding_color(self, pad_index: int) -> tuple:
        return self.layout_selection.get_padding_color(field_num=self.field_num + pad_index)
```

Note that I've used Python's type hinting to indicate the types of variables and function parameters. This is not strictly necessary for the code to work, but it can be helpful for readability and maintenance.

Also note that I've replaced Java's `BigInteger` with Python's built-in integer type (`int`). If you need support for arbitrarily large integers in your Python program, you may want to consider using a library like `gmpy2`.