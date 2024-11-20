Here is the translation of the given Java code into Python:

```Python
class NegationSelector:
    def __init__(self, component):
        self.component = component

    def test(self, t):
        return not self.component.test(t)
```

This Python class `NegationSelector` takes an instance of another selector (`component`) in its constructor and uses it to determine whether the current selection fails. The method `test()` checks if the given object `t` does not satisfy the condition defined by the component, which is equivalent to the Java code's negated test.