Here is the equivalent Python code:

```Python
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
```

Note that Python does not have direct equivalents to Java's `@Slf4j` and `@RestController`. The logging functionality is implemented using the built-in `logging` module, while the RESTful API endpoints are typically handled by a web framework such as Flask or Django.