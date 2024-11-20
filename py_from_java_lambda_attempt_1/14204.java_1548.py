Here is the equivalent Python code:

```Python
class App:
    def __init__(self):
        self.factory = WeaponFactory()

    def main(self):
        builder = lambda: self.factory.builder()
        builder().add(WeaponType.SWORD, Sword)
        builder().add(WeaponType.AXE, Axe)
        builder().add(WeatherType.SPEAR, Spear)
        builder().add(WeatherType.BOW, Bow)

        axe = self.factory.create(WeatherType.AXE)
        print(axe.toString())

if __name__ == "__main__":
    app = App()
    app.main()

class WeaponFactory:
    def factory(self, builder):
        return builder

    def create(self, weapon_type):
        # This is where you would implement the actual creation logic
        pass

class Builder:
    def add(self, weapon_type, constructor):
        pass

class Sword:
    def __init__(self):
        print("Sword created")

    def toString(self):
        return "I'm a sword"

class Axe:
    def __init__(self):
        print("Axe created")

    def toString(self):
        return "I'm an axe"

class Spear:
    def __init__(self):
        print("Spear created")

    def toString(self):
        return "I'm a spear"

class Bow:
    def __init__(self):
        print("Bow created")

    def toString(self):
        return "I'm a bow"
```

Please note that the code is not fully functional as it lacks implementation for `WeaponFactory`, `Builder` and actual creation logic in `create` method.