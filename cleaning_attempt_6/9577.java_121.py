class MixedLayoutBackgroundColorManager:
    def __init__(self, index: int, selection: 'FieldSelection', highlight: 'FieldSelection',
                 backgroundColor: tuple, selectionColor: tuple, highlightColor: tuple,
                 mixedColor: tuple, leftBorderColor: tuple, rightBorderColor: tuple):
        self.index = index
        self.selection = selection
        self.highlight = highlight
        self.backgroundColor = backgroundColor
        self.selectionColor = selectionColor
        self.highlightColor = highlightColor
        self.mixedColor = mixedColor
        self.leftBorderColor = leftBorderColor
        self.rightBorderColor = rightBorderColor

    def get_field_background_color_manager(self, field_num: int) -> 'FieldBackgroundColorManager':
        start_location = FieldLocation(index=self.index, field_num=field_num, x0=0, y0=0)
        end_location = FieldLocation(index=self.index, field_num=field_num+1, x0=0, y0=0)
        range_ = FieldRange(start=start_location, end=end_location)
        is_highlighted = self.highlight.contains_entirely(range_)
        if self.selection.contains_entirely(range_):
            color = mixedColor if is_highlighted else selectionColor
            return FullySelectedFieldBackgroundColorManager(color=color)
        elif not self.selection.contains_entirely(range_) and is_highlighted:
            return FullySelectedFieldBackgroundColorManager(color=highlightColor)
        else:
            field_background_color = highlightColor if is_highlighted else backgroundColor
            return MixedFieldBackgroundColorManager(index=self.index, field_num=field_num,
                                                      manager=self, selection_color=selectionColor,
                                                      background_color=field_background_color)

    def get_background_color(self) -> tuple:
        return self.backgroundColor

    def get_padding_color(self, pad_index: int) -> tuple | None:
        padding_color = None
        if pad_index == 0:
            padding_color = self.leftBorderColor
        elif pad_index == -1:
            padding_color = self.rightBorderColor
        else:
            padding_color = self.get_padding_color_between_fields(pad_index)
        return padding_color

    def get_padding_color_between_fields(self, pad_index: int) -> tuple | None:
        start_location = FieldLocation(index=self.index, field_num=pad_index-1,
                                        x0=int.max_value, y0=int.max_value)
        end_location = FieldLocation(index=self.index, field_num=pad_index, x0=0, y0=0)
        range_ = FieldRange(start=start_location, end=end_location)
        gap_selected = self.selection.contains_entirely(range_)
        gap_highlighted = self.highlight.contains_entirely(range_)
        if gap_selected and gap_highlighted:
            return mixedColor
        elif gap_selected:
            return selectionColor
        elif gap_highlighted:
            return highlightColor
        else:
            return backgroundColor

    def get_selection(self) -> 'FieldSelection':
        return self.selection

    def get_background_color_at_location(self, location: FieldLocation) -> tuple | None:
        is_selected = self.selection.contains(location)
        is-highlighted = self.highlight.contains(location)
        if is_selected and is_highlighted:
            return mixedColor
        elif is_selected:
            return selectionColor
        elif is_highlighted:
            return highlightColor
        else:
            return backgroundColor


class FieldLocation:
    def __init__(self, index: int, field_num: int, x0: int, y0: int):
        self.index = index
        self.field_num = field_num
        self.x0 = x0
        self.y0 = y0

    def contains(self, location) -> bool:
        return True  # Replace this with your actual implementation


class FieldRange:
    def __init__(self, start: 'FieldLocation', end: 'FieldLocation'):
        self.start = start
        self.end = end

    def contains_entirely(self, range_) -> bool:
        return True  # Replace this with your actual implementation


class FullySelectedFieldBackgroundColorManager:
    def __init__(self, color: tuple):
        self.color = color


class MixedFieldBackgroundColorManager:
    def __init__(self, index: int, field_num: int, manager: 'MixedLayoutBackgroundColorManager', selection_color: tuple,
                 background_color: tuple):
        self.index = index
        self.field_num = field_num
        self.manager = manager
        self.selection_color = selection_color
        self.background_color = background_color


class EmptyFieldBackgroundColorManager:
    EMPTY_INSTANCE = None

    def __init__(self, color: tuple):
        pass  # No implementation needed for this class
