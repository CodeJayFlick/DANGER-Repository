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
