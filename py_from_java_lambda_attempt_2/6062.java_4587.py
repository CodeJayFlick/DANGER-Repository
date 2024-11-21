Here is the equivalent Python code:

```Python
class NamespacePath:
    def __init__(self, parent=None, name="", symbol_type=""):
        self.parent = parent
        self.name = name
        self.symbol_type = symbol_type

    @classmethod
    def create(cls, parent=None, name="", symbol_type=""):
        return cls(parent, name, symbol_type)

    def as_namespace_string(self):
        if not self.parent:
            return "ROOT::" + self.name
        else:
            return self.parent.as_namespace_string() + "::" + self.name

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value


class TestNamespacePath:
    def test_create(self):
        nsp = NamespacePath.create(None, "sub1", "NAMESPACE")
        nsp1_1 = NamespacePath.create(nsp, "sub1_1", "NAMESPACE")

        assert nsp.as_namespace_string() == "ROOT::sub1"
        assert nsp1_1.as_namespace_string() == "ROOT::sub1::sub1_1"


    def test_mangling(self):
        ns_slash_a = NamespacePath.create(None, "ns/A", "NAMESPACE")
        ns_space_a = NamespacePath.create(None, "ns A", "NAMESPACE")
        ns_colon_a = NamespacePath.create(None, "ns:A", "NAMESPACE")

        assert ns_slash_a.as_namespace_string() == "ROOT::ns/A"
        assert ns_space_a.as_namespace_string() == "ROOT::ns_1A"
        assert ns_colon_a.as_namespace_string() == "ROOT::ns:1A"

        assert ns_slash_a.name == "ns/A"
        assert ns_space_a.name == "ns 1A"
        assert ns_colon_a.name == "ns:A"


if __name__ == "__main__":
    test = TestNamespacePath()
    test.test_create()
    test.test_mangling()

```

Note: Python does not have a direct equivalent to Java's `@Test` annotation. Instead, you would typically write separate functions for each test case and then call those functions from the main function if you're running them manually.