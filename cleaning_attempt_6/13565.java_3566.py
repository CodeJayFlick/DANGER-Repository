import os
from unittest import TestCase


class RepositoryTest(TestCase):

    REPOSITORY_NAME = "My_Repository"

    def setUp(self):
        self.user_name = ClientUtil.get_user_name()
        parent_dir = create_temp_directory(__name__)
        server_root = os.path.join(parent_dir, "My_Server")
        FileUtilities.delete_dir(server_root)
        os.makedirs(server_root)

        manager = RepositoryManager(server_root, False, 0, False)
        user_manager = manager.get_user_manager()
        user_manager.add_user(self.user_name)

        self.repository = manager.create_repository(self.user_name, REPOSITORY_NAME)


    def test_get_repository_name(self):
        self.assertEqual(REPOSITORY_NAME, self.repository.name)


    def test_set_get_user_list(self):
        users = [User("user-a", User.READ_ONLY), 
                 User("user-b", User.WRITE),
                 User("user-c", User.ADMIN),
                 User("user-d", User.READ_ONLY),
                 User(self.user_name, User.ADMIN)]

        self.repository.set_user_list(self.user_name, users, False)

        reported_users = self.repository.get_user_list(self.user_name)
        self.assertEqual(len(users), len(reported_users))

        for i in range(len(users)):
            self.assertEqual(users[i].name, reported_users[i].name)
            self.assertEqual(users[i].permission_type, reported_users[i].permission_type)


    def test_set_list_bad_user(self):
        users = [User("user-a", User.READ_ONLY), 
                 User("user-b", User.WRITE),
                 User("user-c", User.ADMIN),
                 User("user-d", User.READ_ONLY),
                 User(self.user_name, User.WRITE)]

        try:
            self.repository.set_user_list(self.user_name, users, False)
            self.fail("Should not have been able to change current user's access!")
        except UserAccessException:
            pass

        users[3] = User("user-x", User.ADMIN)
        try:
            self.repository.set_user_list(self.user_name, users, False)
            self.fail("Should not have been able to set the user list!")
        except UserAccessException:
            pass

        users[-1] = User(self.user_name, User.ADMIN)
        self.repository.set_user_list(self.user_name, users, False)

        reported_users = self.repository.get_user_list(self.user_name)
        self.assertEqual(len(users), len(reported_users))

        for i in range(len(users)):
            self.assertEqual(users[i].name, reported_users[i].name)
            self.assertEqual(users[i].permission_type, reported_users[i].permission_type)


    def test_existing_repository(self):
        users = [User("user-a", User.READ_ONLY), 
                 User("user-b", User.WRITE),
                 User("user-c", User.ADMIN),
                 User("user-d", User.READ_ONLY),
                 User(self.user_name, User.ADMIN)]

        self.repository.set_user_list(self.user_name, users, False)

        rep_root = os.path.join(server_root, NamingUtilities.mangle(REPOSITORY_NAME))
        repository = Repository(manager=None, root=rep_root, name=REPOSITORY_NAME)
        assert repository is not None

        reported_users = repository.get_user_list(self.user_name)
        self.assertEqual(len(users), len(reported_users))

        for i in range(len(users)):
            self.assertEqual(users[i].name, reported_users[i].name)
            self.assertEqual(users[i].permission_type, reported_users[i].permission_type)


if __name__ == "__main__":
    unittest.main()
