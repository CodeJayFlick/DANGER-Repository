class Product:
    def __init__(self, product_dao: 'ProductDao', name: str, price: float, expiration_date: str):
        self.product_dao = product_dao
        self.name = name
        self.price = price
        self.expiration_date = expiration_date

    @property
    def sale_price(self) -> float:
        return self.price - self.calculate_discount()

    def save(self) -> None:
        try:
            existing_product = self.product_dao.find_by_name(self.name)
            if existing_product is not None:
                self.product_dao.update(self)
            else:
                self.product_dao.save(self)
        except Exception as e:
            print(f"Error: {e}")

    def calculate_discount(self) -> float:
        today = datetime.date.today()
        days_until_expiration = (self.expiration_date - today).days
        if days_until_expiration < 4:
            return self.price * 0.2
        else:
            return 0

class ProductDao:
    def find_by_name(self, name: str) -> 'Product':
        # TO DO: implement this method
        pass

    def update(self, product: 'Product') -> None:
        # TO DO: implement this method
        pass

    def save(self, product: 'Product') -> None:
        # TO DO: implement this method
        pass
