class User:
    def __init__(self):
        self.name = None
        self.password = None
        self.privilege_list = []
        self.role_list = []

    def __init__(self, name: str, password: str):
        self.name = name
        self.password = password
        self.privilege_list = []
        self.role_list = []

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str):
        self._name = value

    @property
    def password(self) -> str:
        return self._password

    @password.setter
    def password(self, value: str):
        self._password = value

    @property
    def privilege_list(self) -> list:
        return self._privilege_list

    @privilege_list.setter
    def privilege_list(self, value: list):
        self._privilege_list = value

    @property
    def role_list(self) -> list:
        return self._role_list

    @role_list.setter
    def role_list(self, value: list):
        self._role_list = value

    def has_privilege(self, path: str, privilege_id: int) -> bool:
        for privilege in self.privilege_list:
            if privilege.path == path and privilege.id == privilege_id:
                return True
        return False

    def add_privilege(self, path: str, privilege_id: int):
        # TO DO: implement this method
        pass

    def remove_privilege(self, path: str, privilege_id: int):
        # TO DO: implement this method
        pass

    def set_privileges(self, path: str, privileges: set) -> None:
        for i in range(len(self.privilege_list)):
            if self.privilege_list[i].path == path:
                self.privilege_list[i].set_privileges(privileges)
                return

    def has_role(self, role_name: str) -> bool:
        return role_name in self.role_list

    def get_privileges(self, path: str) -> set:
        # TO DO: implement this method
        pass

    def check_privilege(self, path: str, privilege_id: int) -> bool:
        for privilege in self.privilege_list:
            if privilege.path == path and privilege.id == privilege_id:
                return True
        return False

    def __eq__(self, other):
        if not isinstance(other, User):
            return NotImplemented
        return (self.name == other.name 
               and self.password == other.password 
               and self.privilege_list == other.privilege_list 
               and self.role_list == other.role_list)

    def __hash__(self) -> int:
        return hash((self.name, self.password, tuple(self.privilege_list), tuple(self.role_list)))

    @property
    def use_watermark(self):
        return self._use_watermark

    @use_watermark.setter
    def use_watermark(self, value: bool):
        self._use_watermark = value

    def serialize(self) -> bytes:
        data = bytearray()
        SerializeUtils.serialize_string(data, self.name)
        SerializeUtils.serialize_string(data, self.password)

        privilege_list_size = len(self.privilege_list)
        data.extend((privilege_list_size).to_bytes(4, 'big'))
        for path_privilege in self.privilege_list:
            data.extend(path_privilege.serialize())

        use_watermark_byte = 1 if self.use_watermark else 0
        data.append(use_watermark_byte)

        SerializeUtils.serialize_string_list(data, self.role_list)
        return bytes(data)

    def deserialize(self, buffer: bytearray) -> None:
        self.name = SerializeUtils.deserialize_string(buffer)
        self.password = SerializeUtils.deserialize_string(buffer)
        privilege_list_size = int.from_bytes(buffer[:4], 'big')
        self.privilege_list = [PathPrivilege().deserialize(buffer[i:i+8]) for i in range(4, 4 + 8 * privilege_list_size)]
        use_watermark_byte = buffer[-1]
        self.use_watermark = bool(use_watermark_byte)
        self.role_list = SerializeUtils.deserialize_string_list(buffer)

    def __str__(self) -> str:
        return f"User(name='{self.name}', password='{self.password}', " \
               f"privilege_list={self.privilege_list}, role_list={self.role_list}, use_watermark={self.use_watermark})"
