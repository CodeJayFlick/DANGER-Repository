import numpy as np
from PIL import Image, ImageDraw


class BitmapImageFactory:
    def from_file(self, path):
        try:
            bitmap = Image.open(path)
            return BitMapWrapper(bitmap)
        except Exception as e:
            raise IOException("Failed to read image from: " + str(path)) from e

    def from_url(self, url):
        try:
            response = requests.get(url)
            if response.status_code == 200:
                img = Image.open(BytesIO(response.content))
                return BitMapWrapper(img)
            else:
                raise IOException("Failed to read image from URL")
        except Exception as e:
            raise

    def from_image(self, image):
        try:
            if not isinstance(image, Image.Image):
                raise ValueError("only PIL Image allowed")
            return BitMapWrapper(image)
        except Exception as e:
            raise

    def from_ndarray(self, array):
        shape = np.array(array.shape).tolist()
        if len(shape) != 3 or shape[0] > 1:
            raise ValueError("Shape should only have three dimension follow CHW")
        if array.dtype not in [np.uint8, np.int8]:
            raise ValueError("Datatype should be INT8")

        height = int(shape[2])
        width = int(shape[1])

        image_area = width * height
        bitmap = Image.new('RGB', (width, height))
        pixels = []
        for i in range(image_area):
            x = i % width
            y = i // width
            red = array[i].astype(np.uint8).view(np.uint8)[0]
            green = array[i + image_area].astype(np.uint8).view(np.uint8)[0]
            blue = array[i + 2 * image_area].astype(np.uint8).view(np.uint8)[0]

            pixels.append((red, green, blue))

        bitmap.putdata(pixels)
        return BitMapWrapper(bitmap)

    def duplicate(self, type):
        if not isinstance(type, str) or type.lower() != 'int_argb':
            raise ValueError("the type is not supported!")
        return self.from_image(Image.new('RGB', (1, 1), (0,)))

    def to_ndarray(self, manager, flag):
        pixels = []
        channel = 3 if flag == "GRAYSCALE" else 4
        bb = np.zeros((height * width * channel,), dtype=np.uint8)
        bitmap.getpixels(pixels)

        for rgb in pixels:
            red = (rgb >> 16) & 0xFF
            green = (rgb >> 8) & 0FF
            blue = rgb & 0FF

            if flag == "GRAYSCALE":
                gray = (red + green + blue) // 3
                bb[i] = gray
            else:
                bb[i * channel] = red
                bb[(i * channel) + 1] = green
                bb[(i * channel) + 2] = blue

        return manager.create(bb, shape, np.uint8)

    def save(self, os, type):
        if not bitmap.save(os, format=type.upper()):
            raise ValueError("Cannot save image file to output stream File type " + str(type))
