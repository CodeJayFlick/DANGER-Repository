Here is the equivalent Python code:

```Python
import unittest

class TestImageController(unittest.TestCase):

    def test_get_image_path(self):
        image_controller = ImageController()
        self.assertEqual(image_controller.get_image_path(), "/product-image.png")

if __name__ == '__main__':
    unittest.main()
```

Note that there is no direct equivalent to Java's `@Test` annotation in Python. Instead, we define a class that inherits from `unittest.TestCase`, and then define methods with names starting with "test" (e.g., `test_get_image_path`) which are the actual test cases.

Also note that I'm assuming you have an `ImageController` class defined elsewhere in your codebase, as there is no equivalent to Java's constructor (`new ImageController()`) in Python.