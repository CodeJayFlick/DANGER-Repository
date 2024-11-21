Here is the translation of the given Java code into Python:

```Python
class WeaponFactory:
    def __init__(self):
        self.map = {}

    @staticmethod
    def factory(consumer):
        wf = WeaponFactory()
        consumer(wf.put)
        return lambda name: wf.map.get(name)()

    def put(self, weapon_type: str, supplier: callable):
        self.map[weapon_type] = supplier

# Example usage:
def create_weapon(weapon_factory: 'WeaponFactory', weapon_type: str):
    return weapon_factory.create(weapon_type)

class Weapon:
    pass
```

Note that Python does not have direct equivalents for Java's interfaces and static methods. In this translation, the `create` method is an instance method of a class (`WeaponFactory`) rather than a static interface method in Java. The `factory` method is also an instance method of the same class.

Also note that Python does not require explicit type definitions like Java does with its interfaces and classes. However, I have included some basic type hints for clarity and to help catch any potential errors at runtime.