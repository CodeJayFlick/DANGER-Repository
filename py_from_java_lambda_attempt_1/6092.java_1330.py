Here is the translation of the Java code to Python:
```python
import unittest
from resource_manager import ResourceManager
from image_icon import ImageIcon

class ImageManagerTest(unittest.TestCase):
    def test_image_manager_loaded_icon_resources(self):
        default_icon = ResourceManager.get_default_icon()
        
        failed_icons = set()
        for field_name in dir(ImageManager):
            if hasattr(getattr(ImageManager, field_name), 'getType') and \
               getattr(getattr(ImageManager, field_name), 'getType').__name__ == 'ImageIcon':
                value = getattr(ImageManager, field_name)
                if not value or value is default_icon:
                    failed_icons.add(field_name)
        
        self.assertTrue("Some icons failed to load or misconfigured: " + str(failed_icons),
                         len(failed_icons) == 0)

if __name__ == '__main__':
    unittest.main()
```
Note that I had to make some assumptions about the Python code, as there is no direct equivalent of Java's `@Test` annotation. In Python, we use a testing framework like `unittest` and define test methods using the `test_` prefix.

I also assumed that `ResourceManager` and `ImageIcon` are classes or modules in your Python project, and that they have similar functionality to their Java counterparts. If this is not the case, you may need to modify the code accordingly.