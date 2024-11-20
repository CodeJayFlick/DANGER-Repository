class UnionEditorModel:
    def __init__(self, provider, show_in_hex):
        self.headers = ["Length", "Mnemonic", "DataType", "Name", "Comment"]
        self.column_widths = [75, 100, 100, 100, 150]
        self.column_offsets = [0] * len(self.headers)
        self.adjust_offsets()
        self.show_hex_numbers = show_in_hex

    def get_offset_column(self):
        return -1

    def get_length_column(self):
        return 2

    def get_mnemonic_column(self):
        return 1

    def get_data_type_column(self):
        return 2

    def get_name_column(self):
        return 3

    def get_comment_column(self):
        return 4

    def is_cell_editable(self, row_index, column_index):
        if self.get_num_selected_rows() != 1:
            return False
        num_components = self.get_num_components()
        if (row_index < 0) or (row_index > num_components):
            return False
        switch column_index:
            case 2:  # DataType
                if row_index >= 0 and row_index <= num_components:
                    return True
                return False
            case 3:  # FieldName
            case 4:  # Comment
                if row_index >= num_components:
                    return False
                dt = self.get_component(row_index).get_data_type()
                if dt == DataType.DEFAULT:
                    return False
                return True
        return False

    def field_edited(self, value, row_index, column_index):
        if self.applying_field_edit:
            return True  # the one in progress will indicate any errors.
        try:
            self.applying_field_edit = True
            switch column_index:
                case 2:  # DataType
                    self.set_component_data_type(row_index, value)
                    break
                case 3:  # FieldName
                    self.set_component_name(row_index, str(value).strip())
                    break
                case 4:  # Comment
                    self.set_component_comment(row_index, str(value))
                    break
            return True
        except UsrException as e:
            self.status = str(e)
            return False
        finally:
            self.applying_field_edit = False

    def clear_component(self, row_index):
        pass  # clearing not supported

    def is_lockable(self):
        return False

# Begin methods for determining if a type of edit action is allowed.
    def is_bit_field_allowed(self):
        return self.is_single_row_selection()

    def is_array_allowed(self):
        if not self.is_single_row_selection():
            return False
        range = self.selection.get_range(0)
        comp = self.get_component(range.start.index().value())
        return (comp != None and not comp.is_bit_field_component())

# End of methods for determining if a type of edit action is allowed.

    def get_max_add_length(self, index):
        return int.max_value

    def get_max_replace_length(self, current_index):
        return int.max_value

    def get_num_bytes_in_range(self, range):
        num_bytes = 0
        if range != None:
            for i in range.start.index().value() to range.end.index().value():
                comp = self.get_component(i)
                num_bytes = max(num_bytes, comp.length())
        return num_bytes

    def insert(self, row_index, dt, length, name=None, comment=None):
        if dt == DataType.DEFAULT:
            raise InvalidDataTypeException("Inserting undefined bytes is not allowed in a union.")
        try:
            self.get_component(row_index).insert(dt, length)
            return True
        except UsrException as e:
            self.status = str(e)
            return False

    def replace(self, row_index, dt, length, name=None, comment=None):
        if dt == DataType.DEFAULT:
            raise InvalidDataTypeException("Replacing undefined bytes is not allowed in a union.")
        try:
            self.get_component(row_index).replace(dt, length)
            return True
        except UsrException as e:
            self.status = str(e)
            return False

    def replace_range(self, start_row_index, end_row_index, dt, length):
        if length <= 0:
            raise InvalidDataTypeException("Can not replace a range with a " + str(length) + " length data type.")
        try:
            for i in range(end_row_index - 1, start_row_index - 1, -1):
                comp = self.get_component(i)
                dtc_comp = (comp.data_type() if isinstance(comp.data_type(), Composite) else None)
                if dtc_comp and dtc_comp.is_part_of(dt):
                    self.delete_component(i)
            return True
        except UsrException as e:
            self.status = str(e)
            return False

    def remove_dt_from_components(self, comp):
        new_dt = self.view_dtm.get_data_type(comp.data_type_path())
        if new_dt == None:
            return
        num = len(self.components)
        for i in range(num - 1, -1, -1):
            dtc = self.get_component(i)
            dt = dtc.data_type()
            if isinstance(dt, Composite) and dt.is_part_of(new_dt):
                self.delete_component(i)

    def is_at_end(self, row_index):
        return False

# End of the code.
