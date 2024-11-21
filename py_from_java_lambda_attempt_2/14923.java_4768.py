Here is the equivalent Python code:

```Python
import unittest
from unittest.mock import patch

class WizardDaoImplTest(unittest.TestCase):

    def setUp(self):
        self.dao = WizardDaoImpl()

    @patch('Wizard')
    def test_find_by_name(self, wizard_mock):
        all_wizards = self.dao.find_all()
        for spell in all_wizards:
            by_name = self.dao.find_by_name(spell.name)
            self.assertIsNotNone(by_name)
            self.assertEqual(spell.id, by_name.id)
            self.assertEqual(spell.name, by_name.name)

if __name__ == '__main__':
    unittest.main()
```

Note that Python does not have direct equivalent of Java's `@Test` annotation. Instead, you would typically define a test class and use the `unittest` module to run your tests.

Also note that in this translation, I've used Python's built-in `unittest` framework for testing, which is different from JUnit.