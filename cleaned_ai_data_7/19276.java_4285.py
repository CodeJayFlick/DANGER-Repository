class IsUnbreakable:
    def __init__(self):
        pass

    @property
    def description(self) -> str:
        return "Checks whether an item is unbreakable."

    @property
    def examples(self) -> str:
        return "if event-item is unbreakable"

    @property
    def name(self) -> str:
        return "Is Unbreakable"

    @property
    def since(self) -> str:
        return "2.5.1"

    @property
    def required_plugins(self) -> list:
        return ["Minecraft 1.11+"]

    def check(self, item):
        if hasattr(item, 'get_item_meta'):
            meta = item.get_item_meta()
            if hasattr(meta, 'is_unbreakable'):
                return meta.is_unbreakable()

    @property
    def property_name(self) -> str:
        return "unbreakable"
