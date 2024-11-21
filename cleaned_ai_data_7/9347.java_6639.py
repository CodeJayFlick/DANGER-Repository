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
