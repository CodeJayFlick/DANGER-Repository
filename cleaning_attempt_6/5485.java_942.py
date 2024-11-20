class FunctionRepeatableCommentFieldMouseHandler:
    def __init__(self):
        self.SUPPORTED_CLASSES = [FunctionRepeatableCommentFieldLocation]

    def field_element_clicked(self, clicked_object, source_navigatable, location, mouse_event, service_provider):
        comments = self.get_comment(location)
        comment_row = self.get_comment_row(location)
        column = self.get_comment_column(location)
        clicked_word = StringUtilities.find_word(comments[comment_row], column, GoToService.VALID_GOTO_CHARS)

        return self.check_word(clicked_word, service_provider, source_navigatable)

    def get_comment_row(self, program_location):
        return (program_location).get_row()

    def get_comment_column(self, program_location):
        return (program_location).get_char_offset()

    def get_comment(self, program_location):
        return (program_location).get_comment()

    def get_supported_program_locations(self):
        return self.SUPPORTED_CLASSES
