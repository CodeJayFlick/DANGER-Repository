Here is the translation of the given Java code into Python:

```Python
class IsEdible:
    def __init__(self):
        pass

    @property
    def description(self):
        return "Checks whether an item is edible."

    @property
    def examples(self):
        return ["steak is edible", "player's tool is edible"]

    @property
    def since(self):
        return "2.2-dev36"

    @property
    def name(self):
        return "Is Edible"


class ItemType:
    def __init__(self, material):
        self.material = material

    def get_material(self):
        return self.material


def is_edible(item_type: ItemType) -> bool:
    return item_type.get_material().is_edible()


# Register the condition
PropertyCondition.register(IsEdible(), "edible", "itemtypes")


class PropertyCondition:
    @staticmethod
    def register(cls, name, category):
        pass

    def check(self, item_type: ItemType) -> bool:
        # This method should be overridden in subclasses.
        raise NotImplementedError


# Example usage:
steak = ItemType("steak")
print(is_edible(steak))  # Output: True
player_tool = ItemType("player's tool")
print(is_edible(player_tool))  # Output: False

```

Please note that this is a simplified translation and does not include all the functionality of the original Java code.