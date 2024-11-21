Here is the translation of the Java code to Python:

```Python
import unittest

class ActiveCreatureTest(unittest.TestCase):

    def test_execution(self):
        orc = Orc("orc1")
        self.assertEqual("orc1", orc.name())
        self.assertEqual(0, orc.status)
        orc.eat()
        orc.roam()
        orc.kill(0)

if __name__ == '__main__':
    unittest.main()
```

Note that I've used the `unittest` module in Python to write a test case. The equivalent of Java's `@Test` annotation is the method name starting with `test_`.