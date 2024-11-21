Here is the translation of the given Java code into equivalent Python:

```Python
class OrcWeapon:
    def __init__(self, weapon_type: str):
        self.weapon_type = weapon_type

    @property
    def weapon_type(self) -> str:
        return self._weapon_type

    def __str__(self) -> str:
        return f"an orcish {self.weapon_type}"
```

Note that Python does not have a direct equivalent to Java's `@Getter` and `@RequiredArgsConstructor`. The above code uses Python's built-in property decorator (`@property`) for getter functionality, and the constructor is implemented using the `__init__` method.