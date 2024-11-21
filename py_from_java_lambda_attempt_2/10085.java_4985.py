Here is the translation of the Java code into Python:

```Python
class User:
    READ_ONLY = 0
    WRITE = 1
    ADMIN = 2

    ANONYMOUS_USERNAME = "-anonymous-"

    def __init__(self, name: str, permission: int):
        if not isinstance(name, str) or not isinstance(permission, int):
            raise TypeError("Invalid type")
        if permission < User.READ_ONLY or permission > User.ADMIN:
            raise ValueError("Invalid permission value")

        self.name = name
        self.permission = permission

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value: str):
        self._name = value

    @property
    def permission(self):
        return self._permission

    @permission.setter
    def permission(self, value: int):
        if not isinstance(value, int) or value < User.READ_ONLY or value > User.ADMIN:
            raise ValueError("Invalid permission value")
        self._permission = value

    def is_read_only(self):
        return self.permission == User.READ_ONLY

    def has_write_permission(self):
        return self.permission in [User.WRITE, User.ADMIN]

    def is_admin(self):
        return self.permission == User.ADMIN

    def get_permission_type(self):
        return self.permission

    def __str__(self):
        return f"{self.name} ({["read-only", "write", "admin"][self.permission]})"

    def __eq__(self, other: 'User'):
        if not isinstance(other, User):
            return False
        return self.name == other.name and self.permission == other.permission

    def __lt__(self, other: 'User'):
        if not isinstance(other, User):
            raise TypeError("Invalid type")
        if self.name < other.name:
            return True
        elif self.name > other.name:
            return False
        else:
            return self.permission - other.permission < 0

    def __hash__(self):
        return hash((self._name, self._permission))
```

Note that Python does not have a direct equivalent to Java's `Comparable` interface. Instead, we can define the comparison methods (`__lt__`, etc.) directly on the class.