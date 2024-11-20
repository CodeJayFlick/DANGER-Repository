Here is the translation of the given Java code into equivalent Python:

```Python
class OrcBeast:
    def __init__(self, orc_beast=None):
        super().__init__()
        if orc_beast:
            self.weapon = orc_beast.weapon

    @property
    def weapon(self):
        return self._weapon

    @weapon.setter
    def weapon(self, value):
        self._weapon = value

    def copy(self):
        return OrcBeast(self)

    def __str__(self):
        return f"Orcish wolf attacks with {self.weapon}"
```

Note that Python does not have direct equivalent of Java's `@EqualsAndHashCode` and `@RequiredArgsConstructor`. In the above code, I've used Python's built-in methods like `__init__`, `copy()`, and `__str__()`.