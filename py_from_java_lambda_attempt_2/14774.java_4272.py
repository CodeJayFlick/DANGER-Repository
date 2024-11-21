Here is the translation of the given Java code into Python:

```Python
class WizardTest:
    def test_to_string(self):
        names = ["Gandalf", "Dumbledore", "Oz", "Merlin"]
        for name in names:
            self.assertEqual(name, str(Wizard(name)))

if __name__ == "__main__":
    import unittest
    class Test(unittest.TestCase, WizardTest):
        pass

    if __name__ == "__main__":
        unittest.main()
```

Note that Python does not have a direct equivalent to Java's `@Test` annotation. Instead, we define the test method directly in the class and use the built-in `unittest` module for running tests.

Also note that I've assumed you want to run these tests using Python's built-in testing framework (`unittest`). If you're using another testing library or approach, your code may be slightly different.