class URLAnnotatedStringHandler:
    SUPPORTED_ANNOTATIONS = ["url", "hyperlink", "href", "link"]
    INVALID_SYMBOL_TEXT = "@url annotation must have a URL string optionally followed by a display string"

    def create_annotated_string(self, prototype_string: str, text: list[str], program: str) -> str:
        if len(text) <= 1:
            raise AnnotationException(INVALID_SYMBOL_TEXT)

        url = self.get_url_for_string(text[1])

        if not url:
            return f"Invalid URL annotations - not a URL: {text[1]}"

        display_text = str(url)
        if len(text) > 2:
            buffer = ""
            for i in range(2, len(text)):
                buffer += text[i] + " "
            buffer = buffer[:-1]
            display_text = buffer

        return f"{display_text}"

    def get_supported_annotations(self):
        return self.SUPPORTED_ANNOTATIONS


class AnnotationException(Exception):
    pass
