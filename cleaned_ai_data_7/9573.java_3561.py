class LayoutBackgroundColorManager:
    def __init__(self, backgroundColor):
        self.backgroundColor = backgroundColor


class EmptyLayoutBackgroundColorManager(LayoutBackgroundColorManager):
    pass


class MixedLayoutBackgroundColorManager(LayoutBackgroundColorManager):
    def __init__(self, index, selectionIntersect, highlightIntersect,
                 backgroundColor, selectionColor, highlightColor, mixedColor,
                 leftBorderColor, rightBorderColor):
        super().__init__(backgroundColor)
        self.index = index
        self.selectionIntersect = selectionIntersect
        self.highlightIntersect = highlightIntersect
        self.leftBorderColor = leftBorderColor
        self.rightBorderColor = rightBorderColor


def get_layout_color_map(index: int, selection: dict, highlight: dict,
                         backgroundColor: tuple, selectionColor: tuple,
                         highlightColor: tuple, mixedColor: tuple) -> LayoutBackgroundColorManager:
    selection_intersect = {k: v for k, v in selection.items() if index <= k}
    highlight_intersect = {k: v for k, v in highlight.items() if index <= k}

    if not selection_intersect and not highlight_intersect:
        return EmptyLayoutBackgroundColorManager(backgroundColor)

    is_totally_selected = len(selection_intersect) == 1 and all(k >= i for k, v in selection_intersect.items())
    is_totally_highlighted = len(highlight_intersect) == 1 and all(k >= i for k, v in highlight_intersect.items())

    if is_totally_selected and is_totally_highlighted:
        return EmptyLayoutBackgroundColorManager(mixedColor)

    if is_totally_selected and not highlight_intersect:
        return EmptyLayoutBackgroundColorManager(selectionColor)

    if is_totally_highlighted and not selection_intersect:
        return EmptyLayoutBackgroundColorManager(highlightColor)

    start_of_line = (index, 0)
    end_of_line = (index, int(1e9))

    left_border_selected = index in selection
    right_border_selected = index in highlight

    left_border-highlighted = index in highlight
    right_border_highlighted = index in selection

    left_border_color = backgroundColor
    if left_border_selected and left_border_highlighted:
        left_border_color = mixedColor
    elif left_border_selected:
        left_border_color = selectionColor
    elif left_border_highlighted:
        left_border_color = highlightColor

    right_border_color = backgroundColor
    if left_border_selected and right_border_highlighted:
        right_border_color = mixedColor
    elif right_border_selected:
        right_border_color = selectionColor
    elif right_border_highlighted:
        right_border_color = highlightColor

    return MixedLayoutBackgroundColorManager(index, selection_intersect,
                                              highlight_intersect, backgroundColor,
                                              selectionColor, highlightColor,
                                              mixedColor, left_border_color,
                                              right_border_color)
