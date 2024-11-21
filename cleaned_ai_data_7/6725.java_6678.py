class ByteViewerHighlightProvider:
    NO_HIGHLIGHTS = []

    def __init__(self):
        self.highlight_text = None
        self.highlight_color = (255, 255, 0)  # yellow

    def get_highlights(self, text: str, obj: object, field_factory_class: type, cursor_text_offset: int) -> list:
        if text == self.highlight_text:
            return [Highlight(0, len(text) - 1, self.highlight_color)]
        else:
            return NO_HIGHLIGHTS

    def set_text(self, text: str):
        self.highlight_text = text

    def get_text(self) -> str:
        return self.highlight_text

    def set_highlight_color(self, color: tuple):
        self.highlight_color = color
