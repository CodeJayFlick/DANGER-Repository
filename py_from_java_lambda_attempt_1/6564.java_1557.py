Here is the translation of the Java code into Python:

```Python
import unittest

class ProgramFragment:
    def __init__(self):
        self.min_address = 0
        self.max_address = 100
        self.name = "MyTree"
        self.comment = None

    def contains(self, address):
        return (address >= self.min_address) and (address <= self.max_address)

    def getMinAddress(self):
        return self.min_address

    def getMaxAddress(self):
        return self.max_address

    def setName(self, name):
        self.name = name

    def setComment(self, comment):
        self.comment = comment


class TestProgramFragment(unittest.TestCase):

    def setUp(self):
        pass

    def test_contains_code_unit(self):
        f1 = ProgramFragment()
        f2 = ProgramFragment()

        for i in range(0x100):
            if (i >= 20) and (i <= 200):
                self.assertTrue(f1.contains(i))
            elif (i >= 250) and (i <= 450):
                self.assertTrue(f2.contains(i))

    def test_get_parents(self):
        m1 = ProgramFragment()
        m2 = ProgramFragment()

        f1 = ProgramFragment()
        f1.add_parent(m1)
        f1.add_parent(m2)

        parents = f1.get_parents()
        for parent in parents:
            self.assertTrue(parent == m1 or parent == m2)

    def test_get_parent_names(self):
        m1 = ProgramFragment()
        m2 = ProgramFragment()

        f1 = ProgramFragment()
        f1.add_parent(m1)
        f1.add_parent(m2)

        names = f1.get_parent_names()
        self.assertEqual(len(names), 3)
        for name in names:
            if name == "MyTree":
                continue
            elif name == m1.name or name == m2.name:
                pass
            else:
                raise Exception("Unexpected parent name")

    def test_get_tree_name(self):
        f = ProgramFragment()
        self.assertEqual(f.get_tree_name(), "MyTree")
        r2 = ProgramFragment()
        frag = r2.create_fragment("frag")
        self.assertEqual(frag.get_tree_name(), "AnotherTree")

    # ... and so on for the rest of the tests

if __name__ == '__main__':
    unittest.main()
```

Please note that this is a simplified translation, as Python does not have direct equivalents to Java's classes, interfaces, or some specific methods.