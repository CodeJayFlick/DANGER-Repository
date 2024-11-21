class ViewListener:
    def __init__(self):
        pass

    def view_changed(self, fp: 'FieldPanel', index: int, x_offset: int, y_offset: int) -> None:
        """
        Notifies the listener that the top of the screen has changed position.

        Args:
            fp (FieldPanel): The field panel whose view changed.
            index (int): The index of the layout at the top of the screen.
            x_offset (int): The x coordinate of the layout displayed at the left of the screen.
            y_offset (int): The y coordinate of the layout displayed at the top of the screen.

        Returns:
            None
        """
        pass

