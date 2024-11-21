class Role:
    def __init__(self):
        self.name = None
        self.privilege_list = []

    def __init__(self, name):
        self.name = name
        self.privilege_list = []

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def privilege_list(self):
        return self._privilege_list

    @privilege_list.setter
    def privilege_list(self, value):
        self._privilege_list = value

    def has_privilege(self, path, privilege_id):
        from auth_utils import has_privilege
        return has_privilege(path, privilege_id, self.privilege_list)

    def add_privilege(self, path, privilege_id):
        from auth_utils import add_privilege
        add_privilege(path, privilege_id, self.privilege_list)

    def remove_privilege(self, path, privilege_id):
        from auth_utils import remove_privilege
        remove_privilege(path, privilege_id, self.privilege_list)

    def set_privileges(self, path, privileges):
        for path_privilege in self.privilege_list:
            if path_privilege.path == path:
                path_privilege.set_privileges(privileges)
                break

    def get_privileges(self, path):
        from auth_utils import get_privileges
        return get_privileges(path, self.privilege_list)

    def check_privilege(self, path, privilege_id):
        from auth_utils import check_privilege
        return check_privilege(path, privilege_id, self.privilege_list)

    def __eq__(self, other):
        if not isinstance(other, Role):
            return False

        return (self.name == other.name and 
                self.privilege_list == other.privilege_list)

    def __hash__(self):
        return hash((self.name, tuple(self.privilege_list)))

    def serialize(self):
        import io
        from serialize_utils import serialize_string

        buffer = io.BytesIO()
        data_stream = io.BytesIO()

        serialize_string(self.name, data_stream)
        self.privilege_list_size = len(self.privilege_list)

        for path_privilege in self.privilege_list:
            path_privilege.serialize(data_stream)

        try:
            data_stream.write(int.to_bytes(self.privilege_list_size, 4, 'big'))
            buffer.write(data_stream.getvalue())
        except Exception as e:
            print(f"Error: {e}")

        return io.BytesIO(buffer.getvalue())

    def deserialize(self, buffer):
        import io

        self.name = serialize_string(io.BytesIO(buffer.read()))
        self.privilege_list_size = int.from_bytes(buffer.read(4), 'big')
        self.privilege_list = []

        for _ in range(self.privilege_list_size):
            path_privilege = PathPrivilege()
            path_privilege.deserialize(buffer)
            self.privilege_list.append(path_privilege)

    def __str__(self):
        return f"Role(name='{self.name}', privilege_list={self.privilege_list})"
