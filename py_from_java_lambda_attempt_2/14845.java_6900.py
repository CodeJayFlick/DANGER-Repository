Here is the equivalent Python code:

```Python
class Role:
    BORROWER = 'Borrower'
    INVESTOR = 'Investor'

class CustomerCore:
    def __init__(self):
        self.roles = []

    def add_role(self, role: str) -> bool:
        if role in [Role.BORROWER, Role.INVESTOR]:
            self.roles.append(role)
            return True
        else:
            return False

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def rem_role(self, role: str) -> bool:
        if role in [Role.BORROWER, Role.INVESTOR]:
            self.roles.remove(role)
            return True
        else:
            return False

    def get_role(self, role: str, role_type: type) -> object:
        for r in self.roles:
            if isinstance(r, role_type):
                return r
        return None

    def __str__(self) -> str:
        roles_str = ', '.join([role.__name__ for role in self.roles])
        return f'Customer{{roles={roles_str}}}'


import unittest

class TestCustomerCore(unittest.TestCase):

    def test_add_role(self):
        core = CustomerCore()
        self.assertTrue(core.add_role(Role.BORROWER))

    def test_has_role(self):
        core = CustomerCore()
        core.add_role(Role.BORROWER)
        self.assertTrue(core.has_role(Role.BORROWER))
        self.assertFalse(core.has_role(Role.INVESTOR))

    def test_rem_role(self):
        core = CustomerCore()
        core.add_role(Role.BORROWER)

        bRole = core.get_role(Role.BORROWER, Role)
        self.assertIsNotNone(bRole)

        self.assertTrue(core.rem_role(Role.BORROWER))

        empt = core.get_role(Role.BORROWER, Role)
        self.assertIsNone(empt)

    def test_get_role(self):
        core = CustomerCore()
        core.add_role(Role.BORROWER)

        bRole = core.get_role(Role.BORROWER, Role)
        self.assertIsNotNone(bRole)

        nonRole = core.get_role(Role.INVESTOR, Role)
        self.assertIsNone(nonRole)

    def test_to_string(self):
        core = CustomerCore()
        core.add_role(Role.BORROWER)
        self.assertEqual('Customer{roles=[Borrower]}', str(core))

        core = CustomerCore()
        core.add_role(Role.INVESTOR)
        self.assertEqual('Customer{roles=[Investor]}', str(core))

        core = CustomerCore()
        self.assertEqual('Customer{roles=[]}', str(core))


if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `@Test` annotation. Instead, we use the built-in testing framework called `unittest`.