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
