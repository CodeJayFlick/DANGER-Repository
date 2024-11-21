Here is the translation of the Java code to Python:
```python
import os
from PIL import Image

class SuperResolutionTest:
    def test_super_resolution(self):
        image_path = "src/test/resources/"
        fox_image = Image.open(os.path.join(image_path, "fox.png"))
        input_images = [fox_image] * 2

        enhanced_images = SuperResolution.enhance(input_images)

        if enhanced_images is None:
            raise SkipException("Only works for TensorFlow engine.")

        assert len(enhanced_images) == 2
        size = 4 * fox_image.width
        for img in enhanced_images:
            assert img.size == (size, size)
```
Note that I used the `PIL` library to work with images, as there is no direct equivalent of Java's `ImageFactory` and `Image` classes in Python. Additionally, I replaced the `Assert.assertEquals` calls with simple assertions using the `assert` statement.

Also, note that I did not include any imports for the `SkipException` class, as it seems to be a custom exception specific to the TestNG framework used in Java. In Python, you can simply raise a regular `ValueError` or `RuntimeError` instead.