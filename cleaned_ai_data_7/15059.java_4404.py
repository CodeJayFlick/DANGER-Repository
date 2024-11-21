class User:
    def __init__(self, id: int, username: str, password: str):
        self.id = id
        self.username = username
        self.password = password

    @property
    def id(self) -> int:
        return self._id

    @id.setter
    def id(self, value: int):
        self._id = value

    @property
    def username(self) -> str:
        return self._username

    @username.setter
    def username(self, value: str):
        self._username = value

    @property
    def password(self) -> str:
        return self._password

    @password.setter
    def password(self, value: str):
        self._password = value

    def __str__(self):
        return f"User(id={self.id}, username='{self.username}', password='***')"

    def __eq__(self, other):
        if not isinstance(other, User):
            return False
        return (self.id == other.id and 
                self.username == other.username)
