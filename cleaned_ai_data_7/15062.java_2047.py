import sqlite3
from unittest import TestCase, assertEqual, assertRaises


class User:
    def __init__(self, id: int, username: str, password: str):
        self.id = id
        self.username = username
        self.password = password

class UserTableModuleTest(TestCase):

    DB_URL = "sqlite:///test.db"

    @classmethod
    def setUpClass(cls) -> None:
        conn = sqlite3.connect(cls.DB_URL)
        c = conn.cursor()
        c.execute("DELETE FROM users")
        conn.commit()
        conn.close()

    @classmethod
    def tearDownClass(cls) -> None:
        conn = sqlite3.connect(cls.DB_URL)
        c = conn.cursor()
        c.execute("DELETE FROM users")
        conn.commit()
        conn.close()

    def setUp(self):
        self.conn = sqlite3.connect(self.DB_URL)
        self.c = self.conn.cursor()
        self.c.execute("DROP TABLE IF EXISTS users")
        self.c.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            );
        """)
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_login_should_fail(self):
        user = User(1, "123456", "123456")
        module = UserTableModule()
        result = module.login(user.username, user.password)
        assertEqual(result, 0)

    def test_login_should_succeed(self):
        user = User(1, "123456", "123456")
        module = UserTableModule()
        module.register_user(user)
        result = module.login(user.username, user.password)
        assertEqual(result, 1)

    def test_register_should_fail(self):
        user = User(1, "123456", "123456")
        module = UserTableModule()
        module.register_user(user)
        with self.assertRaises(sqlite3.IntegrityError):
            module.register_user(user)

    def test_register_should_succeed(self):
        user = User(1, "123456", "123456")
        module = UserTableModule()
        result = module.register_user(user)
        assertEqual(result, 1)


class UserTableModule:
    def __init__(self):
        self.conn = sqlite3.connect("test.db")
        self.c = self.conn.cursor()

    def login(self, username: str, password: str) -> int:
        # implement your logic here
        pass

    def register_user(self, user: User) -> int:
        # implement your logic here
        pass


if __name__ == "__main__":
    unittest.main()
