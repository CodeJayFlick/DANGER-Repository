import requests
from logging import error as log_error

class ProductInventoryClient:
    def get_product_inventories(self):
        try:
            response = requests.get('http://localhost:51516/inventories')
            if response.status_code == 200 and response.text.strip() != "":
                return int(response.text)
            else:
                return None
        except Exception as e:
            log_error("Error occurred", e)

# Example usage:

client = ProductInventoryClient()
print(client.get_product_inventories())
