Here is the translation of the given Java code into Python:

```Python
class SoldierTest:
    def __init__(self):
        pass  # equivalent to super(Soldier::new)

    def verify_visit(self, unit: 'Soldier', mocked_visitor) -> None:
        import unittest.mock as mockito

        mockito.verify(mocked_visitor).visit_soldier(eq(unit))
```

Note that Python does not have direct equivalents for Java's `package`, `import static`, and `@Override` annotations. The equivalent of the latter is simply using a method with the same name in your subclass.

Also, note that there are no tests or test cases included here as they would typically be implemented separately from the class definition itself.