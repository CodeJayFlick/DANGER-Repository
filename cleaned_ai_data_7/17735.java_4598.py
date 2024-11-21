import os
from unittest import TestCase
from iotdb.auth.entity import Role, PathPrivilege
from iotdb.db.utils import EnvironmentUtils
from iotdb.db.constant import TestConstant
from iotdb.db.auth.manager import LocalFileRoleManager

class LocalFileRoleManagerTest(TestCase):

    def setUp(self):
        EnvironmentUtils.envSetUp()
        self.test_folder = os.path.join(TestConstant.BASE_OUTPUT_PATH, "test")
        if not os.path.exists(self.test_folder):
            os.makedirs(self.test_folder)
        self.manager = LocalFileRoleManager(self.test_folder)

    def tearDown(self):
        try:
            import shutil
            shutil.rmtree(self.test_folder)
        except Exception as e:
            print(f"Error in tear down: {e}")
        EnvironmentUtils.cleanEnv()

    def test(self):

        roles = [Role("role{}".format(i)) for i in range(5)]
        for role in roles:
            for j in range(len(role.get_privilege_list()) + 1):
                path_privilege = PathPrivilege(f"root.a.b.c{j}")
                path_privilege.add_privilege(j)
                role.add_path_privilege(path_privilege)

        # create
        self.assertIsNone(self.manager.get_role(roles[0].name))
        for role in roles:
            self.assertTrue(self.manager.create_role(role.name))
        for role in roles:
            self.assertEqual(role.name, self.manager.get_role(role.name).name)
        self.assertFalse(self.manager.create_role(roles[0].name))
        try:
            self.manager.create_role("too")
        except Exception as e:
            pass
        try:
            self.manager.create_role("rolename ")
        except Exception as e:
            pass

        # delete
        self.assertFalse(self.manager.delete_role("not a role"))
        self.assertTrue(self.manager.delete_role(roles[-1].name))
        self.assertIsNone(self.manager.get_role(roles[-1].name))

        # grant privilege
        role = self.manager.get_role(roles[0].name)
        path = "root.a.b.c"
        privilege_id = 0
        self.assertFalse(role.has_privilege(path, privilege_id))
        self.assertTrue(self.manager.grant_privilege_to_role(role.name, path, privilege_id))
        self.assertTrue(self.manager.grant_privilege_to_role(role.name, path, privilege_id + 1))
        self.assertFalse(self.manager.grant_privilege_to_role(role.name, path, privilege_id))
        role = self.manager.get_role(roles[0].name)
        self.assertTrue(role.has_privilege(path, privilege_id))

        try:
            self.manager.grant_privilege_to_role("not a role", path, privilege_id)
        except Exception as e:
            pass
        try:
            self.manager.grant_privilege_to_role(role.name, path, -1)
        except Exception as e:
            pass

        # revoke privilege
        role = self.manager.get_role(roles[0].name)
        self.assertTrue(self.manager.revoke_privilege_from_role(role.name, path, privilege_id))
        self.assertFalse(self.manager.revoke_privilege_from_role(role.name, path, privilege_id))
        try:
            self.manager.revoke_privilege_from_role("not a role", path, privilege_id)
        except Exception as e:
            pass
        try:
            self.manager.revoke_privilege_from_role(role.name, path, -1)
        except Exception as e:
            pass

        # list roles
        rolenames = sorted(self.manager.list_all_roles())
        for i in range(len(roles) - 1):
            self.assertEqual(roles[i].name, rolenames[i])
