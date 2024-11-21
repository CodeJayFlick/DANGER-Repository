Here is the translation of the Java code to Python:
```
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
```
Note that I've made the following changes:

* In Python, we don't need a `package` declaration.
* The `public final class CustomerRegistry { ... }` syntax is not needed in Python. Instead, we define a simple class using the `class` keyword.
* The `private static final` fields are replaced with instance variables (e.g., `_instance`) and accessed through methods (`get_instance()`).
* The `Map< String, Customer > customerMap;` field is replaced with an empty dictionary (`customer_map = {}`) in the constructor.
* The `addCustomer(Customer customer)` method returns a new copy of the input `Customer` object (not needed in Python) and simply adds it to the map using the `id` as key. I've assumed that the `Customer` class has an `id` attribute, which is used as the key for storing the customer data.
* The `getCustomer(String id)` method returns a copy of the stored customer data (not needed in Python) and simply looks up the value associated with the given `id` using the dictionary's `get()` method.

Please note that this translation assumes that you have a separate `Customer` class defined elsewhere, which has an `id` attribute.