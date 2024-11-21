import requests
import logging

class PriceClient:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

    def get_price(self) -> str:
        try:
            response = requests.get('http://localhost:50006/price')
            if 200 <= response.status_code < 300:
                self.logger.info("Price info received successfully")
                return response.text
            else:
                self.logger.warn("Price info request failed")
        except Exception as e:
            self.logger.error(f"Failure occurred while getting price info: {e}")
        finally:
            return None

if __name__ == "__main__":
    client = PriceClient()
    print(client.get_price())
