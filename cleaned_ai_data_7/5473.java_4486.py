class EolCommentFieldFactory:
    def __init__(self):
        super().__init__()

    @staticmethod
    def get_single_string(comments: list[str], separator_char: str) -> str | None:
        if not comments or len(comments) == 0:
            return None

        buffer = StringBuffer()
        for i in range(1, len(comments)):
            buffer.append(separator_char + comments[i])
        return buffer.toString()

    def get_maximum_lines_to_display(self, max_lines: int, options: dict[str, any]) -> None:
        if max_lines < 1:
            max_lines = 1
            options['maxDisplayLines'] = max_lines

        self.max_display_lines = max_lines

    @staticmethod
    def adjust_comments_for_wrapping(comments: list[str], width: int) -> list[str]:
        adjusted_comments = []
        last_comment_index = len(comments) - 1
        for i in range(0, last_comment_index):
            string = comments[i]
            if not string or not string.strip().endswith(' '):
                adjusted_comments.append(string + ' ')
            else:
                adjusted_comments.append(string)

        if last_comment_index >= 0:
            adjusted_comments.append(comments[last_comment_index])

        return adjusted_comments

    def set_maximum_lines_to_display(self, max_lines: int) -> None:
        self.max_display_lines = max_lines

    @staticmethod
    def convert_to_field_elements(program: any, comments: list[str], current_prefix_string: str | None,
                                   show_prefix: bool, word_wrap: bool, next_row: int) -> list[any]:
        if not word_wrap:
            return [CommentUtils.parse_text_for_annotations(comment, program, current_prefix_string, 0)
                    for comment in comments]

        adjusted_comments = EolCommentFieldFactory.adjust_comments_for_wrapping(comments, width)

        field_elements = []
        for i, row_comment in enumerate(adjusted_comments):
            encoded_row = next_row + i
            field_elements.append(
                CommentUtils.parse_text_for_annotations(row_comment, program, current_prefix_string,
                                                         encoded_row))

        if show_prefix:
            for i, element in enumerate(field_elements):
                start_row_col = element.get_data_location_for_character_index(0)
                encoded_row = start_row_col.row()
                encoded_col = start_row_col.col()

                prefix_field_element = TextFieldElement(current_prefix_string, encoded_row,
                                                          encoded_col)

                field_elements[i] = CompositeFieldElement([prefix_field_element, element])

        return field_elements

    def get_program_location(self, screen_row: int, screen_column: int, bf: any) -> ProgramLocation | None:
        if not isinstance(bf, ListingTextField):
            return None

        obj = bf.get_proxy().get_object()
        if not isinstance(obj, CodeUnit):
            return None

        displayable_eol = DisplayableEOL(obj, self.always_show_repeatable,
                                          self.always_show_ref_repeatables,
                                          self.always_show_automatic,
                                          self.code_unit_format_options.follow_referenced_pointers(),
                                          self.max_display_lines,
                                          self.use_abbreviated-automatic,
                                          self.show_automatic_functions)

        num_lead_columns = 0
        if self.show_semicolon:
            num_lead_columns += len(SEMICOLON_PREFIX) + 1

        if screen_column < num_lead_columns:
            screen_column = 0

        row_col_location = bf.screen_to_data_location(screen_row, screen_column)
        eol_row = row_col_location.row()
        eol_column = row_col_location.col()

        return displayable_eol.get_location(eol_row, eol_column)

    def get_field_location(self, bf: any, index: int | None, field_num: int,
                           loc: ProgramLocation) -> FieldLocation | None:
        if not isinstance(loc, (EOLCommentFieldLocation, RepeatableCommentFieldLocation,
                                RefRepeatCommentFieldLocation, AutomaticCommentFieldLocation)):
            return None

        obj = bf.get_proxy().get_object()
        if not isinstance(obj, CodeUnit):
            return None

        displayable_eol = DisplayableEOL(obj, self.always_show_repeatable,
                                          self.always_show_ref_repeatables,
                                          self.always_show_automatic,
                                          self.code_unit_format_options.follow_referenced_pointers(),
                                          self.max_display_lines,
                                          self.use_abbreviated-automatic,
                                          self.show_automatic_functions)

        row_col_location = displayable_eol.get_rowcol((CommentFieldLocation) loc)
        rcl = bf.data_to_screen_location(row_col_location.row(), row_col_location.col())

        if not has_same_path(bf, loc):
            return None

        return FieldLocation(index=index, field_num=field_num, row=rcl.row(), col=rcl.col())
