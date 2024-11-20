import os
import unittest
from io import IOError

class LocalFileRoleAccessorTest(unittest.TestCase):

    def setUp(self):
        self.test_folder = os.path.join(os.environ.get('BASE_OUTPUT_PATH', ''), 'test')
        if not os.path.exists(self.test_folder):
            os.makedirs(self.test_folder)
        self.accessor = LocalFileRoleAccessor(self.test_folder)

    def tearDown(self):
        try:
            import shutil
            shutil.rmtree(self.test_folder)
        except IOError as e:
            print(f"Error: {e}")

    @unittest.skipIf(os.name != 'posix', "This test is only for Unix-based systems")
    def test(self):

        roles = [Role("role{}".format(i)) for i in range(5)]
        for role in roles:
            for j in range(len(role.get_privilege_list())):
                path_privilege = PathPrivilege("root.a.b.c{}".format(j))
                path_privilege.add_privileges([j])
                role.add_path_privilege(path_privilege)

        # save
        for role in roles:
            self.accessor.save_role(role)

        # load
        for role in roles:
            loaded_role = self.accessor.load_role(role.name)
            assertEqual(self, role, loaded_role)

        self.assertIsNone(self.accessor.load_role("not a role"))

        # delete
        self.assertTrue(self.accessor.delete_role(roles[-1].name))
        self.assertFalse(self.accessor.delete_role(roles[-1].name))
        self.assertIsNone(self.accessor.load_role(roles[-1].name))

        # list
        role_names = sorted(self.accessor.list_all_roles())
        for i, name in enumerate(role_names):
            assertEqual(self, roles[i].name, name)

if __name__ == '__main__':
    unittest.main()
