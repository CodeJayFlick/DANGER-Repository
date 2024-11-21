Here is the equivalent Python code:

```Python
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
```

Please note that Python does not have direct equivalent of Java's `HttpClient` and `HttpResponse`. We are using the popular `requests` library to make HTTP requests. Also, we don't need a separate logging module like SLF4J in this case as Python has its own built-in logging module.

Also, I did not include any kind of error handling for the response status code or parsing the integer from the response text. You might want to add that depending on your specific requirements.