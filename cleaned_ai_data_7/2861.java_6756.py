class UIManagerWrapper:
    color_map = {}
    border_map = {}

    def __init__(self):
        self.color_map.update({
            "Table[Enabled+Selected].textForeground": (255, 255, 255),
            "Table[Enabled+Selected].textBackground": (57, 105, 138),
            "Table.textForeground": (35, 35, 36),
            "Table.alternateRowColor": (237, 243, 254),
            "Table:\"Table.cellRenderer\".background": (255, 255, 255)
        })

        self.border_map.update({
            "Table.focusCellHighlightBorder": ((2, 5, 2, 5), ),
            "Table.cellNoFocusBorder": ((2, 5, 2, 5), )
        })

    def get_color(self, text):
        if not hasattr(UIManagerWrapper, 'color_map'):
            UIManagerWrapper.color_map = self.color_map
        return tuple([c/255.0 for c in UIManagerWrapper.color_map.get(text, (0, 0, 0))])

    def get_border(self, text):
        if not hasattr(UIManagerWrapper, 'border_map'):
            UIManagerWrapper.border_map = self.border_map
        border = UIManagerWrapper.border_map.get(text)
        return [int(c) for c in border]
