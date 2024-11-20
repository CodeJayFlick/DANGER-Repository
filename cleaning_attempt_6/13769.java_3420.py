import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)

class ImageController:
    def get_image_path(self):
        LOGGER.info("Successfully found image path")
        return "/product-image.png"

if __name__ == "__main__":
    controller = ImageController()
    print(controller.get_image_path())
