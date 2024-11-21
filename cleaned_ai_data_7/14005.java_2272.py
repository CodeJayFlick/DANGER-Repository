class Product:
    def __init__(self, id=None, name="", price=0.0, cost=0.0, supplier=""):
        self.id = id
        self.name = name
        self.price = price
        self.cost = cost
        self.supplier = supplier

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = value
        return self

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value
        return self

    @property
    def price(self):
        return self._price

    @price.setter
    def price(self, value):
        self._price = value
        return self

    @property
    def cost(self):
        return self._cost

    @cost.setter
    def cost(self, value):
        self._cost = value
        return self

    @property
    def supplier(self):
        return self._supplier

    @supplier.setter
    def supplier(self, value):
        self._supplier = value
        return self

    def __str__(self):
        return f"Product(id={self.id}, name='{self.name}', price={self.price}, cost={self.cost}, supplier='{self.supplier}')"
