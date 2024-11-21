Here is the equivalent Python code:

```Python
import requests
import logging

class ProductInformationClient:
    def get_product_title(self):
        try:
            response = requests.get('http://localhost:51515/information')
            return response.text
        except Exception as e:
            logging.error("An error occurred", exc_info=True)

if __name__ == "__main__":
    client = ProductInformationClient()
    print(client.get_product_title())
```

Note that this Python code does not include the same level of logging and exception handling as the original Java code. You may want to add additional try/except blocks or use a more robust error-handling mechanism depending on your specific requirements.

Also, note that I did not translate the `@Slf4j` annotation from Java to Python because there is no direct equivalent in Python for this type of logging setup.