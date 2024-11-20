class GHtmlTextPane:
    def __init__(self):
        self.content_type = "text/html"

    def get_selected_text(self):
        html = self.get_prettified_html()
        if html is not None:
            return html
        else:
            return super().getSelectedText()

    def get_prettified_html(self):
        selected_html = self.get_selected_html_text()
        converted = HTMLUtilities.fromHTML(selected_html)
        return converted

    def get_selected_html_text(self):
        doc = self.getDocument()
        start = self.getSelectionStart()
        end = self.getSelectionEnd()
        try:
            start_pos = doc.createPosition(start)
            end_pos = doc.createPosition(end)

            start_offset = start_pos.getOffset()
            end_offset = end_pos.getOffset()
            size = end_offset - start_offset
            string_writer = StringWriter(size)
            editor_kit().write(string_writer, doc, start_offset, size)
            text = string_writer.toString()
            return text

        except (BadLocationException, IOException) as e:
            print("Unable to extract HTML text from editor pane", e)

    def get_editor_kit(self):
        # This method is not implemented in the original Java code
        pass


class StringWriter:
    def __init__(self, size):
        self.size = size

    def write(self, doc, start_offset, size):
        raise NotImplementedError("This method should be overridden")


def main():
    ghtml_text_pane = GHtmlTextPane()
    # Use the class methods
