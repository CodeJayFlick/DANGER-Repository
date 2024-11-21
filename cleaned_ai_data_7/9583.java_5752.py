class FieldInputListener:
    def __init__(self):
        pass

    def key_pressed(self, ev: object, index: int, field_num: int, row: int, col: int, field: object) -> None:
        """
        Called when the FieldPanel receives a KeyEvent that it doesn't handle.

        :param ev: The KeyEvent generated when the user presses a key.
        :param index: The index of the layout the cursor was on when the key was pressed.
        :param field_num: The field index of the field the cursor was on when the key was pressed.
        :param row: The row in the field the cursor was on when the key was pressed.
        :param col: The column in the field the cursor was on when the key was pressed.
        :param field: The current field the cursor was on when the key was pressed.
        """
        pass
