class CustomerRegistry:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(CustomerRegistry, cls).__new__(cls)
            cls._instance.customer_map = {}
        return cls._instance

    @classmethod
    def get_instance(cls):
        return cls._instance

    def add_customer(self, customer: dict) -> dict:
        self.customer_map[customer['id']] = customer
        return customer

    def get_customer(self, id: str) -> dict or None:
        return self.customer_map.get(id)
