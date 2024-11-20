Here is the translation of the Java code into Python:

```Python
class UnionDataTypeTest:
    def __init__(self):
        self.union = None

    @classmethod
    def setUp(cls):
        cls.union = cls.create_union("TestUnion")
        cls.union.add(0, ByteDataType(), "field1", "Comment1")
        cls.union.add(1, WordDataType(), None, "Comment2")
        cls.union.add(2, DWordDataType(), "field3", None)
        cls.union.add(3, ByteDataType(), "field4", "Comment4")

    @classmethod
    def create_union(cls, name):
        return UnionDataType(name)

    # ... other methods ...

if __name__ == "__main__":
    setUp()
```

Note that Python does not have direct equivalents for Java's `@Before` and `@Test` annotations. Instead, you would typically put your setup code in a separate method (like the one above) and call it before running each test.

Also note that this is just an example translation of the provided Java code into Python; actual implementation details may vary depending on specific requirements and constraints.