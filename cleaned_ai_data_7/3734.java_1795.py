class EnumTableModel:
    NAME_COL = 0
    VALUE_COL = 1
    COMMENT_COL = 2

    NAME = "Name"
    VALUE = "Value"
    COMMENT = "Comment"

    column_names = [NAME, VALUE, COMMENT]

    def __init__(self, enuum, editor_panel):
        self.enuum = enuum
        self.editor_panel = editor_panel
        self.initialize()

    def get_name(self):
        return "Enum Editor"

    def get_row_count(self):
        return self.enuum.get_count()

    def get_column_count(self):
        return len(self.column_names)

    def get_column_class(self, column_index):
        return str

    def is_cell_editable(self, row_index, column_index):
        return True

    def get_column_value_for_row(self, v, column_index):
        if column_index == self.NAME_COL:
            return v.name
        elif column_index == self.VALUE_COL:
            mask = 0xffffffffffffffffL
            value = long_to_hex(v.value & mask)
            return "0x" + value
        else:  # COMMENT COL
            return v.comment

    def get_model_data(self):
        return self.enum_entry_list

    def set_value_at(self, value, row_index, column_index):
        size = len(self.enum_entry_list)

        if row_index < 0 or row_index >= size:
            return

        notify_listener = False
        entry = self.enum_entry_list[row_index]
        old_name = entry.name
        old_comment = entry.comment
        old_value = entry.value

        if column_index == self.NAME_COL:
            new_name = str(value)
            if new_name != old_name and is_name_valid(new_name):
                self.enuum.remove(old_name)
                self.enuum.add(new_name, old_value, old_comment)
                entry.name = new_name
                notify_listener = True

        elif column_index == self.VALUE_COL:
            try:
                if str(value) == "":
                    return  # Ignore attempts to erase the value
                else:
                    new_value = parse_long(str(value))
                    if new_value != old_value:
                        self.enuum.remove(old_name)
                        self.enuum.add(new_name, new_value, old_comment)
                        entry.value = new_value
                        notify_listener = True

            except (ValueError, IndexError):
                editor_panel.set_status_message("Invalid number entered")

        elif column_index == self.COMMENT_COL:
            if str(value) != old_comment and value is not None:
                self.enuum.remove(old_name)
                self.enuum.add(new_name, new_value, str(value))
                entry.comment = str(value)
                notify_listener = True

        if notify_listener:
            editor_panel.state_changed(None)
            self.is_changed = True
            editor_panel.restore_selection(old_name, True)

    def get_column_name(self, column):
        return self.column_names[column]

    def set_table_sort_state(self, sort_state):
        self.editor_panel.stop_cell_editing()
        super().set_table_sort_state(sort_state)

    def create_sort_comparator(self, column_index):
        if column_index == self.NAME_COL:
            return EnumNameComparator()
        else:  # VALUE COL
            return EnumValueComparator()

    @property
    def enum(self):
        return self.enuum

    @property
    def has_changes(self):
        return self.is_changed

    def dispose(self):
        super().dispose()
        self.is_changed = False
        self.enum_entry_list.clear()

    def get_row(self, name):
        for i in range(len(self.enum_entry_list)):
            if self.enum_entry_list[i].name == name:
                return i
        return -1

    def get_name_at(self, index):
        return self.enum_entry_list[index].name

    def set_enum(self, enuum, is_changed):
        self.enuum = enuum
        self.is_changed = is_changed
        self.initialize()

    def add_entry(self, after_row):
        value = find_next_value(after_row)
        name = get_unique_name()
        comment = ""
        new_entry = EnumEntry(name, value, comment)

        try:
            self.enuum.add(new_entry.name, long(value), comment)
            index = get_index_for_row_object(new_entry)
            if index < 0:
                index = -index - 1
            self.enum_entry_list.append(new_entry)

            fire_table_data_changed()
            self.is_changed = True

        except (ValueError, IndexError):
            editor_panel.set_status_message("Invalid number entered")
            return -1

    def find_next_value(self, after_row):
        if len(self.enum_entry_list) == 0:
            return 0
        elif after_row < 0 or after_row >= len(self.enum_entry_list):
            after_row = 0
        value = self.enum_entry_list[after_row].value + 1

        while True:
            if is_value_too_big_for_length(value, self.enuum.length) and not is_too_big(value):
                return value
            elif is_too_big(value):
                break
            else:
                value += 1

    def is_value_too_big_for_length(self, value, length):
        if length < 8:
            max = (1 << (8 * length)) - 1
            return value > max or value < 0
        else:
            return False

    def is_too_big(self, value):
        return self.is_value_too_big_for_length(value, self.enuum.length)

    def get_unique_name(self):
        name = "New_Name"
        count = 0
        while enum_contains_name(name):
            count += 1
            name = f"New_Name ({count})"
        return name

    def initialize(self):
        self.enum_entry_list = []
        names = self.enuum.get_names()
        for name in names:
            self.enum_entry_list.append(EnumEntry(name, long_to_hex(long(self.enuum.value(name))), ""))
        fire_table_data_changed()

    def is_name_valid(self, name):
        if not name or len(name) == 0:
            editor_panel.set_status_message("Please enter a name")
            return False
        elif enum_contains_name(name):
            editor_panel.set_status_message(f"{name} already exists")
            return False
        else:
            return True

    def enum_contains_name(self, name):
        try:
            self.enuum.value(name)
            return True
        except (ValueError, IndexError):
            return False


class EnumEntry:
    def __init__(self, name, value, comment):
        self.name = name
        self.value = long(value[2:])
        self.comment = str(comment)


def fire_table_data_changed():
    pass  # TO DO: implement this method


def parse_long(s):
    return int(long_to_hex(int(s)), 16)


def long_to_hex(l):
    return hex(l)[2:]
