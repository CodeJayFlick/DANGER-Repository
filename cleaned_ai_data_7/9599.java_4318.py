class FieldSelectionHelper:
    @staticmethod
    def is_string_selection(selection):
        if selection.get_num_ranges() != 1:
            return False
        field_range = selection.get_field_range(0)
        start = field_range.get_start()
        end = field_range.get_end()
        return start.get_index().equals(end.get_index()) and start.get_field_number() == end.get_field_number()

    @staticmethod
    def get_field_selection_text(selection, panel):
        if not FieldSelectionHelper.is_string_selection(selection):
            return None
        return FieldSelectionHelper.get_text_for_field(selection.get_field_range(0), panel)

    @staticmethod
    def get_all_selected_text(selection, panel):
        buffy = ""
        num_ranges = selection.get_num_ranges()
        for i in range(num_ranges):
            field_range = selection.get_field_range(i)
            buffy += FieldSelectionHelper.get_text_for_range(field_range, panel) + " "
        return buffy.strip()

    @staticmethod
    def get_text_for_field(field_range, panel):
        start_loc = field_range.get_start()
        index = start_loc.get_index()
        field_num = start_loc.get_field_number()
        start_row = start_loc.get_row()
        start_col = start_loc.get_col()
        end_loc = field_range.get_end()
        end_row = end_loc.get_row()
        end_col = end_loc.get_col()

        layout = panel.get_layout_model().get_layout(index)
        if layout is None:
            return None
        field = layout.get_field(field_num)
        if field is None:
            return None
        text = field.get_text()
        if text is None:
            return None

        start_pos = field.screen_location_to_text_offset(start_row, start_col)
        end_pos = field.screen_location_to_text_offset(end_row, end_col)

        if start_pos < 0 or start_pos >= len(text) or end_pos < 0 or end_pos > len(text):
            return None
        return text[start_pos:end_pos]

    @staticmethod
    def get_text_for_range(field_range, panel):
        start_loc = field_range.get_start()
        end_loc = field_range.get_end()

        buffy = ""
        for i in range(int(start_loc.get_index()), int(end_loc.get_index()) + 1):
            layout = panel.get_layout_model().get_layout(BigInteger(i))
            if layout is None:
                return None
            text = ""

            if i == start_loc.get_index():
                if i == end_loc.get_index():
                    # only one index, use the end values
                    text = FieldSelectionHelper.get_text_for_fields_in_layout(layout, field_range, start_loc.get_field_number(), end_loc.get_field_number())
                else:
                    text = FieldSelectionHelper.get_text_for_fields_in_layout(layout, field_range, start_loc.get_field_number(), layout.get_num_fields())
            elif i != int(end_loc.get_index()):
                text = FieldSelectionHelper.get_text_for_fields_in_layout(layout, field_range, 0, layout.get_num_fields())
            else:
                text = FieldSelectionHelper.get_text_for_fields_in_layout(layout, field_range, 0, end_loc.get_field_number())

            buffy += text

            if i != int(end_loc.get_index()):
                buffy += " "

        return buffy.strip()

    @staticmethod
    def get_text_for_fields_in_layout(layout, field_range, start_field_num, end_field_num):
        buffy = ""
        for i in range(start_field_num, end_field_num):
            field = layout.get_field(i)
            if field is None:
                continue

            buffy += field.get_text_with_line_separators()
            if i != end_field_num - 1:
                buffy += " "

        return buffy
