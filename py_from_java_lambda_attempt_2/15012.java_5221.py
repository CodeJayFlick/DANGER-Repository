Here is the translation of the given Java code into Python:

```Python
class MassSelectorTest:
    def test_mass(self):
        light_creature = object()
        heavy_creature = object()

        def get_mass(obj):
            if obj == light_creature:
                return 50.0
            elif obj == heavy_creature:
                return 2500.0

        light_selector = MassSmallerThanOrEqSelector(500.0)

        self.assertTrue(light_selector.test(light_creature, get_mass))
        self.assertFalse(light_selector.test(heavy_creature, get_mass))

class MassSmallerThanOrEqSelector:
    def __init__(self, threshold):
        self.threshold = threshold

    def test(self, creature, get_mass):
        return get_mass(creature) <= self.threshold
```

Note that Python does not have direct equivalent of Java's `when` and `thenReturn` methods. Instead, we define a function `get_mass` to simulate the behavior of these methods.