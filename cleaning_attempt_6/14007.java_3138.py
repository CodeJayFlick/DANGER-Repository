# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class ProductResource:
    def __init__(self, products: list):
        self.products = products

    def get_all_products_for_admin(self) -> list:
        return [ProductDtoResponsePrivate(id=p.id, name=p.name, cost=p.cost, price=p.price)
                for p in self.products]

    def get_all_products_for_customer(self) -> list:
        return [ProductDtoResponsePublic(id=p.id, name=p.name, price=p.price)
                for p in self.products]

    def save(self, create_product_dto: ProductDtoRequestCreate):
        product = Product(id=len(self.products), name=create_product_dto.name,
                          supplier=create_product_dto.supplier, price=create_product_dto.price,
                          cost=create_product_dto.cost)
        self.products.append(product)

    @property
    def products(self) -> list:
        return self._products

class ProductDtoResponsePrivate:
    def __init__(self, id: int, name: str, cost: float, price: float):
        self.id = id
        self.name = name
        self.cost = cost
        self.price = price

class ProductDtoRequestCreate:
    def __init__(self, name: str, supplier: str, price: float, cost: float):
        self.name = name
        self.supplier = supplier
        self.price = price
        self.cost = cost

class Product:
    def __init__(self, id: int, name: str, supplier: str, price: float, cost: float):
        self.id = id
        self.name = name
        self.supplier = supplier
        self.price = price
        self.cost = cost
