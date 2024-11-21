Here is the equivalent Python code:

```Python
import unittest

class SoldierUnitTest(unittest.TestCase):

    def test_get_unit_extension(self):
        unit = SoldierUnit("SoldierUnitName")

        self.assertIsNotNone(unit.get_unit_extension("SoldierExtension"))
        self.assertIsNone(unit.get_unit_extension("SergeantExtension"))
        self.assertIsNone(unit.get_unit_extension("CommanderExtension"))

if __name__ == '__main__':
    unittest.main()
```

Note that Python does not have a direct equivalent to Java's `@Test` annotation. Instead, we define test methods using the name of the method starting with "test_". The `unittest.TestCase` class provides various assertion methods like `assertIsNone`, `assertNotEqual`, etc., which are used in these tests.

Also note that Python does not have a direct equivalent to Java's static imports (`import static`). Instead, we can import specific classes or functions from other modules.