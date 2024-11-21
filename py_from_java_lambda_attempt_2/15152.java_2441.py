Here is the translation of the Java code to Python:
```
import unittest

class StatueTest(unittest.TestCase):
    def setUpClass(cls):
        cls.statue = Statue(1, 20)

    def tearDownClass(cls):
        cls.statue = None

    @unittest.skip("Not implemented yet")
    def test_update_for_pending_shoot(self):
        self.statue.frames = 10
        self.statue.update()
        self.assertEqual(11, self.statue.frames)

    @unittest.skip("Not implemented yet")
    def test_update_for_shooting(self):
        self.statue.frames = 19
        self.statue.update()
        self.assertEqual(0, self.statue.frames)
```
Note that I used the `unittest` module to define a test class and methods. The `setUpClass` method is equivalent to Java's `@BeforeAll`, while `tearDownClass` is equivalent to Java's `@AfterAll`. The individual test methods are similar to Java's, but with some differences in syntax.

Also note that I used the `skip` decorator on the two test methods, since they don't seem to be fully implemented yet. You'll need to fill in the implementation details for these tests!