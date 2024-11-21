class FieldBackgroundColorManager:
    def __init__(self):
        pass

    def get_background_color(self) -> tuple or None:
        """Returns the overall background color for the entire field."""
        # TO DO: implement this method
        return None  # default value if not implemented

    def get_selection_highlights(self, row: int) -> list:
        """Return a list of highlights (background colors ranges) for a given row of text in the field."""
        # TO DO: implement this method
        return []  # default value if not implemented

    def get_padding_color(self, pad_index: int) -> tuple or None:
        """Returns the color for the right or left padding within the field."""
        # TO DO: implement this method
        return None  # default value if not implemented
