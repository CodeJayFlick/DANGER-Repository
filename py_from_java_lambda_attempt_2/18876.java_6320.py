Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from parameterized import parameterized

class TestNamespace(unittest.TestCase):

    def test_null_and_empty(self):
        with self.assertRaises(NullPointerException):
            Namespace.of(None)

        with self.assertRaises(NullPointerException):
            Namespace.of([])

        with self.assertRaises(NullPointerException):
            Namespace.parse(None)

        namespace = Namespace.of()
        self.assertEqual(namespace.name(), "")

        namespace = Namespace.parse("")
        self.assertEqual(namespace.name(), "")

    def test_one_element(self):
        namespace = Namespace.of(["foo"])
        self.assertEqual(namespace.name(), "foo")
        self.assertFalse(namespace.is_empty())

    @parameterized.expand([
        ([["a", "b"]], "a.b"),
        ([["a", "b", "c"]], "a.b.c"),
    ])
    def test_namespace_from_elements(self, elements, expected_namespace):
        namespace = Namespace.of(elements)
        self.assertEqual(namespace.name(), expected_namespace)
        self.assertFalse(namespace.is_empty())

        namespace = Namespace.of([*elements])
        self.assertEqual(namespace.name(), expected_namespace)
        self.assertFalse(namespace.is_empty())

    @parameterized.expand([
        ("a", "a"),
        ("a.b", "a.b"),
        ("a.b.c", "a.b.c"),
    ])
    def test_namespace_parsing(self, identifier, expected_namespace):
        namespace = Namespace.parse(identifier)
        self.assertEqual(namespace.name(), expected_namespace)
        self.assertFalse(namespace.is_empty())

    @parameterized.expand([
        ([["."]], "x"),
        ([["a"], ["."]]), "x"),
        ([["a", "b", "c"], ["."]]), "x"),
    ])
    def test_invalid_elements(self, elements):
        with self.assertRaises(ValueError):
            Namespace.of(elements)

        with self.assertRaises(ValueError):
            Namespace.of([*elements])

if __name__ == "__main__":
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `@Test` annotation. Instead, we use the built-in `unittest` module to define test cases and run them using a testing framework like `parameterized`.