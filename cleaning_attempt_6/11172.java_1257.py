class UserAccessTableModel:
    def __init__(self, current_user, user_list, service_provider):
        self.current_user = current_user
        self.users = list(user_list)

    @property
    def name(self):
        return "User Access"

    def set_value_at(self, value, row_index, column_index):
        if 0 <= row_index < len(self.users):
            user = self.users[row_index]
            if column_index == 1:
                user = User(user.name, bool(value))
            elif column_index == 2:
                user = User(user.name, not bool(value) and (User.READ_ONLY or User.WRITE))
            elif column_index == 3:
                user = User(user.name, bool(value) and User.ADMIN)
            self.users.remove(row_index)
            self.users.insert(row_index, user)

    def is_cell_editable(self, row_index, column_index):
        if not self.current_user.is_admin():
            return False
        elif column_index in [1, 2, 3]:
            row_user = self.users[row_index]
            current_user = User(self.current_user.name)
            return row_user != current_user and (column_index == 1 or column_index == 3)

    def create_table_column_descriptor(self):
        descriptor = TableColumnDescriptor()
        descriptor.add_visible_column(UserColumn())
        descriptor.add_visible_column(ReadOnlyColumn())
        descriptor.add_visible_column(ReadWriteColumn())
        descriptor.add_visible_column(AdminColumn())
        return descriptor

    @property
    def data_source(self):
        return self.users


class User:
    READ_ONLY, WRITE = 0, 1
    ADMIN = 2

    def __init__(self, name, permission):
        self.name = name
        self.permission = permission


class TableColumnDescriptor:
    def add_visible_column(self, column):
        pass


class AbstractDynamicTableColumn:
    def get_column_name(self):
        raise NotImplementedError("get_column_name")


class UserColumn(AbstractDynamicTableColumn):
    @property
    def column_name(self):
        return "User"

    def get_value(self, row_object, settings, data, service_provider):
        return row_object.name


class ReadOnlyColumn(AbstractDynamicTableColumn):
    @property
    def column_name(self):
        return "Read Only"

    def get_value(self, row_object, settings, data, service_provider):
        return row_object.permission == User.READ_ONLY


class ReadWriteColumn(AbstractDynamicTableColumn):
    @property
    def column_name(self):
        return "Read/Write"

    def get_value(self, row_object, settings, data, service_provider):
        return not row_object.is_admin() and (row_object.permission != User.ADMIN)


class AdminColumn(AbstractDynamicTableColumn):
    @property
    def column_name(self):
        return "Admin"

    def get_value(self, row_object, settings, data, service_provider):
        return row_object.permission == User.ADMIN


# Usage:
user_access_table_model = UserAccessTableModel("current_user", ["user1", "user2"], None)
