Here is the translation of the given Java code into Python:

```Python
class SpaceStationIss(SpaceStationMir):
    def __init__(self, left, top, right, bottom):
        super().__init__(left, top, right, bottom)

    def collision(self, gameObject):
        gameObject.collision_resolve(self)
```

Please note that this is a direct translation of the given Java code into Python. The `package` declaration and copyright notice are not translated as they do not have any equivalent in Python.