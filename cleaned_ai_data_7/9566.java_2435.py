class EmptyFieldBackgroundColorManager:
    EMPTY_INSTANCE = None
    EMPTY_HIGHLIGHT_LIST = []

    def __init__(self):
        pass

    def get_selection_highlights(self, row: int) -> list:
        return self.EMPTY_HIGHLIGHT_LIST

    def get_background_color(self) -> tuple:
        return (0, 0, 0, 0)

    def get_padding_color(self, pad_index: int) -> tuple:
        return (0, 0, 0, 0)
