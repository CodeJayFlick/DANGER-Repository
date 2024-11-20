Here's your Java code translated into Python:

```Python
class ProductDto:
    class Request:
        class Create:
            def __init__(self):
                self.name = None
                self.price = None
                self.cost = None
                self.supplier = None

            @property
            def name(self):
                return self._name

            @name.setter
            def name(self, value):
                self._name = value

            @property
            def price(self):
                return self._price

            @price.setter
            def price(self, value):
                self._price = value

            @property
            def cost(self):
                return self._cost

            @cost.setter
            def cost(self, value):
                self._cost = value

            @property
            def supplier(self):
                return self._supplier

            @supplier.setter
            def supplier(self, value):
                self._supplier = value


    class Response:
        class Public(ProductDto.Request.Create):
            def __init__(self):
                super().__init__()
                self.id = None

            @property
            def id(self):
                return self._id

            @id.setter
            def id(self, value):
                self._id = value

            @property
            def name(self):
                return self._name

            @name.setter
            def name(self, value):
                self._name = value

            @property
            def price(self):
                return self._price

            @price.setter
            def price(self, value):
                self._price = value


        class Private(ProductDto.Request.Create):
            def __init__(self):
                super().__init__()

            @property
            def cost(self):
                return self._cost

            @cost.setter
            def cost(self, value):
                self._cost = value


class Id:
    def get_id(self):
        pass


class Name(Id):
    def get_name(self):
        pass


class Price(Name):
    def get_price(self):
        pass


class Cost(Price):
    def get_cost(self):
        pass


class Supplier(Cost):
    def get_supplier(self):
        pass
```

Please note that Python does not support direct translation of Java interfaces and enums. The above code is a best-effort attempt to translate the provided Java code into equivalent Python classes, methods, and properties.