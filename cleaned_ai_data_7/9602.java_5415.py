class HighlightFactory:
    def get_highlights(self, field: 'Field', text: str, cursor_text_offset: int) -> list:
        """
        Returns the highlights for the given text.

        Args:
            field (Field): The field that is requesting the highlight.
            text (str): The text to be considered for highlighting.
            cursor_text_offset (int): The position in the given text of the cursor. A -1 indicates
                the cursor is not in this field.

        Returns:
            list: An array of highlights to be rendered.
        """
        pass  # Implement me!
