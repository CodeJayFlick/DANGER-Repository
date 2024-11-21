Here is the equivalent Python code:

```Python
import numpy as np
from PIL import Image
import io
import requests

class BufferedImageFactoryTest:
    def test_load_image(self):
        response = requests.get("https://github.com/deepjavalibrary/djl/raw/master/examples/src/test/resources/dog_bike_car.jpg")
        img = Image.open(io.BytesIO(response.content))
        array = np.array(img)
        assert array.shape == (img.height, img.width, 3)

    def test_form_nd_array(self):
        array = np.arange(0.0, 12.0).reshape((3, 2, 2)).astype(np.float32)
        image = Image.fromarray(array.astype(np.uint8))
        converted = np.array(image).transpose((2, 0, 1)).astype(np.float32)
        assert np.allclose(array, converted)

if __name__ == "__main__":
    test_load_image()
    test_form_nd_array()

```

Please note that Python does not have direct equivalent of Java's `NDManager` and `ImageFactory`. We are using NumPy for numerical operations and PIL (Python Imaging Library) to load the image.