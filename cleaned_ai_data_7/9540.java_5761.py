class ClippingTextField:
    DOT_DOT_DOT_WIDTH = 12

    def __init__(self, startX: int, width: int, text_element: 'FieldElement', num_data_rows: int, hl_factory: 'HighlightFactory'):
        self.startX = startX
        self.width = width
        self.numDataRows = num_data_rows
        self.text_element = text_element
        self.hl_factory = hl_factory
        self.preferred_width = text_element.get_string_width()
        self.clip(width)

    def clip(self, available_width: int):
        original_text_element = self.text_element
        w = self.text_element.get_string_width()

        if w <= available_width:
            return

        is_clipped = True
        length = self.text_element.get_max_characters_for_width(available_width - DOT_DOT_DOT_WIDTH)
        self.text_element = self.text_element.substring(0, length)

    def contains(self, x: int, y: int) -> bool:
        if (x >= self.startX and x < self.startX + self.width) and \
           (y >= -self.text_element.get_height_above() and y < self.text_element.get_height_below()):
            return True
        return False

    def get_col(self, row: int, x: int) -> int:
        pos = max(x - self.startX, 0)
        return self.text_element.get_max_characters_for_width(pos)

    def get_cursor_bounds(self, row: int, col: int) -> 'Rectangle':
        if row != 0:
            return None

        x = find_x(col) + self.startX
        return Rectangle(x, -self.text_element.get_height_above(), 2,
                          self.text_element.get_height_above() + self.text_element.get_height_below())

    def get_height(self) -> int:
        return self.text_element.get_height_above() + self.text_element.get_height_below()

    # ... and so on for the rest of the methods
