Here is the translation of the Java code to Python:

```Python
import unittest
from your_module import AuthorityChecker  # replace 'your_module' with actual module name


class TestAuthorityChecker(unittest.TestCase):

    def setUp(self):
        self.authorizer = BasicAuthorizer.getInstance()
        self.user = User("user", "password")

    def tearDown(self):
        EnvironmentUtils.cleanEnv()

    @unittest.skipIf(not hasattr(AuthorityChecker, 'check'), "AuthorityChecker.check method not found")
    def test_authority_checker(self):

        # Grant privileges
        self.authorizer.createUser(self.user.getName(), self.user.getPassword())
        for privilege_type in [PrivilegeType.INSERT_ TIMESERIES,
                                PrivilegeType.CREATE_ROLE,
                                PrivilegeType.CREATE_USER,
                                PrivilegeType.READ_TIMESERIES,
                                PrivilegeType.DELETE_TIMESERIES,
                                # ... and so on
                               ]:
            self.authorizer.grantPrivilegeToUser(self.user.getName(), "root.laptop.d1", privilege_type.ordinal())

        # Test authority checker
        self.assertTrue(AuthorityChecker.check(self.user.getName(),
                                                 [PartialPath("root.laptop.d1")],
                                                 OperatorType.INSERT,
                                                 self.user.getName()))
        self.assertTrue(AuthorityChecker.check("root", None, None, None))
        self.assertTrue(AuthorityChecker.check(self.user.getName(),
                                                 [PartialPath("root.laptop.d1")],
                                                 OperatorType.CREATE_ROLE,
                                                 self.user.getName()))

        # Test empty list
        self.assertFalse(AuthorityChecker.check(self.user.getName(), [], OperatorType.INSERT, self.user.getName()))
```

Note: This is a simplified translation of the Java code to Python and may not work as-is due to differences in syntax and semantics between the two languages. You will likely need to modify it further to suit your specific needs.