import logging

# Define a logger instance
logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)

class CustomerDto:
    def __init__(self, id: str, first_name: str, last_name: str):
        self.id = id
        self.first_name = first_name
        self.last_name = last_name

class Product:
    def __init__(self, id: int, name: str, supplier: str, price: float, cost: float):
        self.id = id
        self.name = name
        self.supplier = supplier
        self.price = price
        self.cost = cost

def print_customer_details(all_customers):
    for customer in all_customers:
        LOGGER.info(customer.first_name)

if __name__ == "__main__":
    # Example 1: Customer DTO
    customers = [
        CustomerDto("1", "Kelly", "Brown"),
        CustomerDto("2", "Alfonso", "Bass")
    ]

    customer_resource = {
        'getAllCustomers': lambda: customers,
        'delete': lambda id: [customer for customer in customers if customer.id != id],
        'save': lambda new_customer: customers.append(new_customer)
    }

    LOGGER.info("All customers:-")
    all_customers = customer_resource['getAllCustomers']()
    print_customer_details(all_customers)

    LOGGER.info("----------------------------------------------------------")
    LOGGER.info(f"Deleting customer with id {customers[0].id}")
    customer_resource['delete'](customers[0])
    all_customers = customer_resource['getAllCustomers']()
    print_customer_details(all_customers)

    LOGGER.info("----------------------------------------------------------")
    LOGGER.info("Adding customer three")
    new_customer = CustomerDto("3", "Lynda", "Blair")
    customer_resource['save'](new_customer)
    all_customers = customer_resource['getAllClients']()
    print_customer_details(all_customers)

    # Example 2: Product DTO
    products = [
        Product(1, 'TV', 'Sony', 1000.0, 1090.0),
        Product(2, 'microwave', 'Delonghi', 1000.0, 1090.0),
        Product(3, 'refrigerator', 'Botsch', 1000.0, 1090.0),
        Product(4, 'airConditioner', 'LG', 1000.0, 1090.0)
    ]

    product_resource = {
        'getAllProductsForAdmin': lambda: products,
        'getAllProductsForCustomer': lambda: [product for product in products if product.name != "PS5"],
        'save': lambda new_product: products.append(new_product)
    }

    LOGGER.info("####### List of products including sensitive data just for admins:\n  {}".format('\n  '.join(map(str, product_resource['getAllProductsForAdmin']()))))
    LOGGER.info("####### List of products for customers:\n  {}".format('\n  '.join(map(str, product_resource['getAllProductsForCustomer']()))))

    LOGGER.info("####### Going to save Sony PS5 ...")
    create_product_request = {
        'name': "PS5",
        'cost': 1000.0,
        'price': 1220.0,
        'supplier': "Sony"
    }
    product_resource['save'](Product(**create_product_request))
    LOGGER.info("####### List of products after adding PS5: {}".format('\n  '.join(map(str, product_resource['getProducts']()))))

