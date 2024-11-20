class CondIsOccluding:
    def __init__(self):
        self.register()

    @staticmethod
    def register():
        pass  # This method should be implemented to perform registration in Python equivalent.

    def check(self, item: 'ItemType') -> bool:
        return item.get_material().is_occluding

    def get_property_name(self) -> str:
        return "occluding"


class ItemType:
    @staticmethod
    def get_material() -> object:
        pass  # This method should be implemented to provide the material of an item in Python equivalent.

    def is_occluding(self) -> bool:
        pass  # This method should be implemented to check whether a material occludes or not in Python equivalent.
