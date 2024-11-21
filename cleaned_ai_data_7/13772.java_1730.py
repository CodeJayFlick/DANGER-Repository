import logging

logging.basicConfig(level=logging.INFO)

class PriceController:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def get_price(self):
        self.logger.info("Successfully found price info")
        return "20"

if __name__ == "__main__":
    controller = PriceController()
    print(controller.get_price())
