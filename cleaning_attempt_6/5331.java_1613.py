class HighlightProvider:
    EMPTY_HIGHLIGHT = []

    def get_highlights(self, text: str, obj: object, field_factory_class: type, cursor_text_offset: int) -> list:
        """
        Get the highlights appropriate for the given text, object, and FieldFactory class.

        Args:
            text (str): The entire text contained in the field.
            obj (object): Object that provides the information to be rendered.
            field_factory_class (type): Class that indicates what type of field is being rendered.
            cursor_text_offset (int): Cursor position within the given text or -1 if no cursor.

        Returns:
            list: An array of highlight objects that indicate the location within the text string to be highlighted.
        """
        pass  # TO DO: implement this method
