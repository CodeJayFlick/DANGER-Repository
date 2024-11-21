Here is the equivalent Python code:

```Python
import unittest

class UnitTest(unittest.TestCase):

    def test_const_get_set(self):
        name = "testName"
        unit = Unit(name)
        self.assertEqual(name, unit.name)

        new_name = "newName"
        unit.set_name(new_name)
        self.assertEqual(new_name, unit.name)


if __name__ == '__main__':
    unittest.main()
```

Note that Python does not have a direct equivalent to Java's `@Test` annotation. Instead, we define the test function as a method of the class and use the `unittest.TestCase` class from the built-in `unittest` module.

Also note that I used the `self.assertEqual()` and `self.assertRaises()` methods provided by the `unittest.TestCase` class instead of static imports like in Java.