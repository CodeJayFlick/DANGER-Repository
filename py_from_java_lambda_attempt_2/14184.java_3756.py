Here is the equivalent Python code:

```Python
import unittest

class CommanderUnitTest(unittest.TestCase):

    def test_get_unit_extension(self):
        unit = CommanderUnit("CommanderUnitName")

        self.assertIsNone(unit.get_unit_extension("SoldierExtension"))
        self.assertIsNone(unit.get_unit_extension("SergeantExtension"))
        self.assertIsNotNone(unit.get_unit_extension("CommanderExtension"))

if __name__ == '__main__':
    unittest.main()
```

Note that Python does not have a direct equivalent to Java's `@Test` annotation. Instead, we define the test function using the name of the test method (e.g., `test_get_unit_extension`). The `unittest.TestCase` class provides methods like `assertIsNone`, `assertNotEqual`, etc. for asserting conditions in tests.

Also note that Python does not have a direct equivalent to Java's static imports (`import static org.junit.jupiter.api.Assertions.*;`). Instead, we can import the specific assertion functions directly (e.g., `from unittest import assertIsNone`).

Finally, Python has its own way of running unit tests. We use the `unittest.main()` function at the end of our test script to run all the tests defined in that file.