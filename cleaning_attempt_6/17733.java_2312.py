class User:
    def __init__(self, name: str, password: str):
        self.name = name
        self.password = password
        self.privilege_list = []
        self.role_list = []

    def set_privilege_list(self, privilege_list):
        self.privilege_list = privilege_list

    def set_privileges(self, path: str, privileges: list):
        pass  # Not implemented in Python equivalent

    def serialize(self) -> bytes:
        return f"User{{name='{self.name}', password='{self.password}', privilegeList={str(self.privilege_list)}, roleList=[], useWaterMark=False, lastActiveTime=0}}".encode()

    def deserialize(self, serialized: bytes):
        pass  # Not implemented in Python equivalent

def test_user():
    user = User("user", "password")
    path_privilege = {"path": "root.ln", "privileges": ["INSERT_TIMESERIES"]}
    user.privilege_list.append(path_privilege)
    assert str(user) == f"User{{name='user', password='password', privilegeList=[{str(path_privilege)}], roleList=[], useWaterMark=False, lastActiveTime=0}}"

    user1 = User("user1", "password1")
    serialized_user = user.serialize()
    user1.deserialize(serialized_user)
    assert str(user) == f"User{{name='user', password='password', privilegeList=[{str(path_privilege)}], roleList=[], useWaterMark=False, lastActiveTime=0}}"

if __name__ == "__main__":
    test_user()

