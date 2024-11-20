class VariableCommentFieldMouseHandler:
    def __init__(self):
        self.SUPPORTED_CLASSES = [VariableCommentFieldLocation]

    def field_element_clicked(self, clicked_object, source_navigatable, location, mouse_event, service_provider):
        comments = self.get_comment(location)
        comment_row = self.get_comment_row(location)
        column = self.get_comment_column(location)
        clicked_word = StringUtilities.find_word(comments[comment_row], column, GoToService.VALID_GOTO_CHARS)

        return self.check_word(clicked_word, service_provider, source_navigatable)

    def get_comment_row(self, program_location):
        return 0

    def get_comment_column(self, program_location):
        if isinstance(program_location, VariableCommentFieldLocation):
            return program_location.get_char_offset()
        else:
            raise ValueError("Invalid Program Location")

    def get_comment(self, program_location):
        if isinstance(program_location, VariableCommentFieldLocation):
            return [program_location.get_comment()]
        else:
            raise ValueError("Invalid Program Location")

    def get_supported_program_locations(self):
        return self.SUPPORTED_CLASSES

class StringUtilities:
    @staticmethod
    def find_word(comments, column, valid_goto_chars):
        # implement your logic here to find the word in comments at given column and row
        pass

class GoToService:
    VALID_GOTO_CHARS = ['']  # implement your logic here for valid goto chars
