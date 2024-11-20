import unittest

class TestImageController(unittest.TestCase):

    def test_get_image_path(self):
        image_controller = ImageController()
        self.assertEqual(image_controller.get_image_path(), "/product-image.png")

if __name__ == '__main__':
    unittest.main()
