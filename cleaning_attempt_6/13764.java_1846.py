class MobileProduct:
    def __init__(self):
        self._price = None

    @property
    def price(self):
        return self._price

    @price.setter
    def price(self, value):
        self._price = value
