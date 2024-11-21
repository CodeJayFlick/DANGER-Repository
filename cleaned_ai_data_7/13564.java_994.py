import os
import unittest
from tempfile import TemporaryDirectory

class RepositoryManagerTest(unittest.TestCase):

    def setUp(self):
        self.root = None
        with TemporaryDirectory() as tempdir:
            parent_dir = os.path.join(tempdir, "Repositories")
            if not os.path.exists(parent_dir):
                os.makedirs(parent_dir)
            self.root = parent_dir
            write_user_list(os.path.join(self.root))

    def tearDown(self):
        if self.root is not None and os.path.exists(self.root):
            for root, dirs, files in os.walk(self.root):
                for f in files:
                    os.remove(os.path.join(root, f))
                for d in dirs:
                    shutil.rmtree(os.path.join(root, d))
            os.rmdir(self.root)

    def test_create_repository_manager(self):
        self.mgr = RepositoryManager(self.root, False, 0, False)
        assert self.mgr is not None

        user_names = self.mgr.get_all_users("User_0")
        self.assertEqual(len(user_names), 10)

    def test_create_repository_manager_with_anonymous(self):
        self.mgr = RepositoryManager(self.root, False, 0, True)
        assert self.mgr is not None

        user_names = self.mgr.get_all_users("User_0")
        self.assertEqual(len(user_names), 10)

        anonymous_user_name = UserManager.ANONYMOUS_USERNAME
        user_names = self.mgr.get_all_users(anonymous_user_name)
        self.assertEqual(len(user_names), 0)

    def test_create_repository(self):
        self.mgr = RepositoryManager(self.root, False, 0, False)

        repository = self.mgr.create_repository("User_0", "REPOSITORY_A")
        assert repository is not None

    def test_create_repository_anonymous(self):
        self.mgr = RepositoryManager(self.root, False, 0, True)

        repository = self.mgr.create_repository("User_0", "REPOSITORY_A")
        assert repository is not None

        try:
            self.mgr.create_repository(UserManager.ANONYMOUS_USERNAME, "REPOSITORY_B")
            self.fail("Expected UserAccessException")
        except UserAccessException as e:
            pass  # expected exception

    def test_create_duplicate_repository(self):
        self.mgr = RepositoryManager(self.root, False, 0, False)
        repository1 = self.mgr.create_repository("User_0", "REPOSITORY_A")

        try:
            self.mgr.create_repository("User_5", "REPOSITORY_A")
            self.fail("Expected DuplicateFileException!")
        except DuplicateFileException as e:
            pass  # expected exception

    def test_get_repository(self):
        self.mgr = RepositoryManager(self.root, False, 0, True)
        repository1 = self.mgr.create_repository("User_0", "REPOSITORY_A")
        add_users("User_0", True, repository1)

        repository2 = self.mgr.create_repository("User_0", "REPOSITORY_B")
        add_users("User_0", False, repository2)

        repository3 = self.mgr.create_repository("User_9", "REPOSITORY_9A")
        add_users("User_9", False, repository3)

        repository4 = self.mgr.create_repository("User_9", "REPOSITORY_9B")
        add_users("User_9", False, repository4)

        self.assertEqual(repository1, self.mgr.get_repository("User_1", "REPOSITORY_A"))
        self.assertEqual(repository1, self.mgr.get_repository(UserManager.ANONYMOUS_USERNAME, "REPOSITORY_A"))

        try:
            self.mgr.get_repository(anonymous_user_name, "REPOSITORY_B")
            self.fail("Expected UserAccessException!")
        except UserAccessException as e:
            pass  # expected exception

        self.assertEqual(repository2, self.mgr.get_repository("User_2", "REPOSITORY_B"))
        self.assertEqual(repository3, self.mgr.get_repository("User_3", "REPOSITORY_9A"))
        self.assertEqual(repository4, self.mgr.get_repository("User_4", "REPOSITORY_9B"))

    def test_get_repository_bad_user(self):
        self.mgr = RepositoryManager(self.root, False, 0, False)
        repository1 = self.mgr.create_repository("User_0", "REPOSITORY_A")

        try:
            self.mgr.get_repository("unknownUser", "REPOSITORY_A")
            self.fail("Should not have been able to get the repository!")
        except UserAccessException as e:
            pass  # expected exception

        try:
            self.mgr.get_repository(anonymous_user_name, "REPOSITORY_A")
            self.fail("Should not have been able to get the repository!")
        except UserAccessException as e:
            pass  # expected exception

    def add_users(self, current_user, allow_anonymous_access, repository):
        users = [User(f"User_{i}", User.READ_ONLY) for i in range(10)]
        if f"User_{current_user}".startswith("User_"):
            type = User.ADMIN
        else:
            type = User.READ_ONLY

    def write_user_list(self, repository_root):
        user_names = ["User_" + str(i) for i in range(10)]

        ServerTestUtil.create_users(repository_root, user_names)

    def delete_files(self, parent_dir):
        files = os.listdir(parent_dir)
        for file in files:
            if os.path.isdir(os.path.join(parent_dir, file)):
                self.delete_files(os.path.join(parent_dir, file))
                os.rmdir(os.path.join(parent_dir, file))
            else:
                os.remove(os.path.join(parent_dir, file))

if __name__ == "__main__":
    unittest.main()
