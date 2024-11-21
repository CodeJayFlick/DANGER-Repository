class VersionHistoryTableModel:
    DATE = "Version Date"
    VERSION = "Version"
    USER = "User"
    COMMENTS = "Comments"

    VERSION_COL = 0
    DATE_COL = 1
    USER_COL = 2
    COMMENTS_COL = 3

    def __init__(self, versions):
        self.version_list = []
        for version in versions:
            self.version_list.append(version)
        self.default_sort_state = TableSortState.create_default_sort_state(self.VERSION_COL, False)

    @property
    def name(self):
        return "Version History"

    @property
    def column_count(self):
        return len(self.column_names)

    @property
    def column_classes(self):
        if hasattr(self, 'column_classes'):
            return self.column_classes
        else:
            result = []
            for i in range(len(self.column_names)):
                if i == self.DATE_COL:
                    result.append(str)
                elif i == self.VERSION_COL:
                    result.append(int)
                else:
                    result.append(str)
            self.column_classes = tuple(result)
            return self.column_classes

    @property
    def column_names(self):
        if hasattr(self, 'column_names'):
            return self.column_names
        else:
            self.column_names = (self.VERSION, self.DATE, self.USER, self.COMMENTS)
            return self.column_names

    @property
    def get_column_name(self, column_index):
        return self.column_names[column_index]

    def refresh(self, new_versions):
        self.version_list = []
        for version in new_versions:
            self.version_list.append(version)
        self.fire_table_data_changed()

    def get_version_at(self, row):
        if 0 <= row < len(self.version_list):
            return self.version_list[row]
        else:
            return None

    @property
    def column_value_for_row(self, version, column_index):
        if column_index == self.VERSION_COL:
            return version.get_version()
        elif column_index == self.DATE_COL:
            return datetime.datetime.fromtimestamp(version.get_create_time())
        elif column_index == self.USER_COL:
            return version.get_user()
        elif column_index == self.COMMENTS_COL:
            return version.get_comment()

    @property
    def model_data(self):
        return self.version_list

    @property
    def is_sortable_column(self, column_index):
        return True


class TableSortState:
    def __init__(self, default_sort_state=False):
        self.default_sort_state = default_sort_state

    @staticmethod
    def create_default_sort_state(column_index, descending):
        return TableSortState(descending)


import datetime
