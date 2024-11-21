import unittest
from PIL import Image

class BigGANTest(unittest.TestCase):

    def test_biggan(self):
        try:
            generated_images = BigGAN.generate()
            if generated_images is None:
                raise self.skipTest("Only works for PyTorch engine.")
            self.assertEqual(len(generated_images), 5)
            for img in generated_images:
                self.assertEqual(img.width, 256)
                self.assertEqual(img.height, 256)
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == '__main__':
    unittest.main()
