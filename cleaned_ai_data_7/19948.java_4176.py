class Slot:
    def __init__(self):
        pass

    @property
    def item(self) -> 'ItemStack':
        raise NotImplementedError("Subclasses must implement this method")

    @item.setter
    def set_item(self, item: 'ItemStack'):
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def amount(self):
        raise NotImplementedError("Subclasses must implement this method")

    @amount.setter
    def set_amount(self, amount):
        raise NotImplementedError("Subclasses must implement this method")

    def __str__(self) -> str:
        return self.__str__(None, False)

    def is_same_slot(self, other: 'Slot') -> bool:
        raise NotImplementedError("Subclasses must implement this method")


class ItemStack:
    pass


def debuggable(cls):
    cls.debug = lambda *args, **kwargs: None
    return cls

@debuggable
class Debuggable:
    def __init__(self):
        self.debug = lambda *args, **kwargs: None
