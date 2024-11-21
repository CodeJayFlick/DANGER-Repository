Here is the translation of the given Java code into Python:

```Python
import unittest

class WeekdayTest(unittest.TestCase):

    def test_to_string(self):
        for weekday in Weekday:
            self.assertIsNotNone(str(weekday))
            self.assertEqual(weekday.name().upper(), str(weekday).upper())

if __name__ == '__main__':
    unittest.main()
```

Note that Python does not have a direct equivalent to Java's `@Test` annotation. Instead, you would define test methods within the class and use the `unittest.TestCase` class provided by the `unittest` module.

Also note that in this translation, I assumed that there is an enum called `Weekday`. If such an enum doesn't exist in your Python codebase, you will need to create it or replace its usage with something else.