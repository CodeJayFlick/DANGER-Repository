Here is the translation of the given Java code into Python:

```Python
import os
from PIL import Image
import io
import numpy as np


class GImageConverter:
    def __init__(self, image_file):
        self.image_file = image_file

    def to_buffered_image(self):
        buffered_image = Image.open(self.image_file)
        
        if buffered_image is None:
            raise Exception("No image provider for " + str(self.image_file))

        width, height = buffered_image.size
        pixels = np.array(buffered_image)

        out = io.BytesIO()

        p = 0
        while p < len(pixels):
            blue = int((pixels[p][2] & 0xff))
            green = int((pixels[p][1] & 0xff))
            red = int((pixels[p][0] & 0xff))
            alpha = ~int((pixels[p][3] & 0xff)) # bit invert the alpha byte...

            out.write(int.to_bytes(red, 1, 'big'))
            out.write(int.to_bytes(green, 1, 'big'))
            out.write(int.to_bytes(blue, 1, 'big'))
            out.write(int.to_bytes(alpha, 1, 'big'))

            p += 4

        return out.getvalue()


def main():
    img = os.path.join(os.environ['HOME'], "Mobile_Devices", "images", "apple_logo_line_1.PNG")
    raw = os.path.join(os.environ['HOME'], "Mobile_Devices", "images", "apple_logo_line_1.RAW")

    image_file = open(img, 'rb')
    
    converter = GImageConverter(image_file)
    image_bytes = converter.to_buffered_image()

    with open(raw, 'wb') as raw_out:
        raw_out.write(image_bytes)

if __name__ == "__main__":
    main()
```

Please note that this Python code does not include the same functionality as the original Java code. The `GImage` class and its methods are missing in this translation.