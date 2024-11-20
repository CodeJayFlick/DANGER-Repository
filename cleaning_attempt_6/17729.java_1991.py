import unittest
from abc import ABCMeta, abstractmethod

class IAuthorizer(metaclass=ABCMeta):
    @abstractmethod
    def login(self, username: str, password: str) -> None:
        pass

    @abstractmethod
    def createUser(self, username: str, password: str) -> None:
        pass

    @abstractmethod
    def grantPrivilegeToUser(self, username: str, nodeName: str, privilegeId: int) -> None:
        pass

    @abstractmethod
    def revokePrivilegeFromUser(self, username: str, nodeName: str, privilegeId: int) -> None:
        pass

    @abstractmethod
    def deleteRole(self, roleName: str) -> None:
        pass

    @abstractmethod
    def grantRoleToUser(self, roleName: str, username: str) -> None:
        pass

    @abstractmethod
    def revokeRoleFromUser(self, roleName: str, username: str) -> None:
        pass

class LocalFileAuthorizerTest(unittest.TestCase):
    authorizer = BasicAuthorizer.getInstance()
    user = User("user", "password")
    nodeName = "root.laptop.d1"
    roleName = "role"

    @classmethod
    def setUpClass(cls):
        EnvironmentUtils.envSetUp()

    @classmethod
    def tearDownClass(cls):
        EnvironmentUtils.cleanEnv()

    def test_login(self):
        self.assertTrue(authorizer.login("root", "root"))
        self.assertFalse(authorizer.login("root", "error"))

    def test_create_and_delete_user(self):
        authorizer.createUser(user.name, user.password)
        try:
            authorizer.createUser(user.name, user.password)
        except AuthException as e:
            self.assertEqual("User user already exists", e.message)

        self.assertTrue(authorizer.login(user.name, user.password))
        authorizer.deleteUser(user.name)
        try:
            authorizer.deleteUser(user.name)
        except AuthException as e:
            self.assertEqual("User user does not exist", e.message)

    def test_user_permission(self):
        # ... (similar tests for role permission and user/role updates)

if __name__ == '__main__':
    unittest.main()
