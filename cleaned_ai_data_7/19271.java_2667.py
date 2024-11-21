class IsSolid:
    def __init__(self):
        self.description = "Checks whether an item is solid."
        self.name = "Is Solid"
        self.since = "2.2-Dev36"

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, value):
        self._description = value

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def since(self):
        return self._since

    @since.setter
    def since(self, value):
        self._since = value

    def __call__(self, item_type: 'ItemType') -> bool:
        if isinstance(item_type, ItemType):
            material = item_type.get_material()
            return material.is_solid
        else:
            raise TypeError("Invalid type")

class PropertyCondition:
    pass

class ItemType:
    def get_material(self) -> object:
        # This method should be implemented based on your actual use case.
        pass

    @property
    def is_solid(self):
        # This property should be implemented based on your actual use case.
        return False
