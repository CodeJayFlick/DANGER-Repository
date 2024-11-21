Here is the translation of the Java code to Python:
```
import io

class ImageTransferable:
    def __init__(self, img):
        self.data = img

    def get_transfer_data_flavors(self):
        return [io.DataFlavor('image')]

    def is_data_flavor_supported(self, flavor):
        return flavor == 'image'

    def get_transfer_data(self, flavor):
        if not isinstance(flavor, str) or flavor != 'image':
            raise io.UnsupportedFlavorException
        return self.data

# Example usage:
img = ...  # assume you have an Image object here
transferable = ImageTransferable(img)
```
Note that Python does not have a built-in equivalent to Java's `DataFlavor` class, so I created a simple wrapper around the flavor string. Also, in Python, we don't need explicit getters and setters for attributes like we do in Java.

Also note that this code assumes you are using some kind of image library or module (e.g., Pillow) to work with images in Python. The `Image` object is not a built-in Python type.