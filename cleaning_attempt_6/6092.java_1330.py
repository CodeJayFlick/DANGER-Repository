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
