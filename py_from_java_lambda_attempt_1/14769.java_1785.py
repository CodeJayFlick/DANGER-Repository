Here is the translation of the given Java code into Python:

```Python
# The MIT License
# Copyright © 2014-2021 Ilkka Seppälä

class WizardTower:
    """WizardTower interface."""

    def enter(self, wizard):
        pass


if __name__ == "__main__":
    # This is not part of the original code but added for demonstration purposes.
    wiz_tower = WizardTower()
    my_wizard = "SomeMagicWand"
    wiz_tower.enter(my_wizard)
```

Please note that Python does not have direct equivalent to Java's interface. Instead, it uses abstract classes or protocols (in the context of type hinting). In this translation, I used a regular class with an `enter` method as per your request.