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
